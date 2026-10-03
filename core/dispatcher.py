import json
import importlib.util
import os
import sys

def dispatch(parsed_data, patterns_map_path='patterns_map.json'):
    """
    Cari pattern yang cocok dari parsed_data, lalu jalankan solver.
    Return {"flag": bytes, "method": str, "detail": str} jika sukses.
    """
    if not os.path.exists(patterns_map_path):
        return {"flag": None, "method": "dispatcher", "detail": "patterns_map.json not found"}
        
    try:
        with open(patterns_map_path, 'r', encoding='utf-8') as f:
            patterns = json.load(f)
    except Exception as e:
        return {"flag": None, "method": "dispatcher", "detail": f"Error loading JSON: {e}"}
        
    # Urutkan iterasi: prioritaskan yang statusnya 'DONE', pisahkan factordb ke urutan paling akhir (fallback offline first)
    local_done = [(k, v) for k, v in patterns.items() if v.get('impl_status') == 'DONE' and 'factordb' not in v.get('module', '')]
    remote_done = [(k, v) for k, v in patterns.items() if v.get('impl_status') == 'DONE' and 'factordb' in v.get('module', '')]
    done_patterns = local_done + remote_done
    
    import re
    flag_pattern = re.compile(rb'[A-Za-z0-9_]+\{[ -~]{3,100}\}')

    for name, pat in done_patterns:
        trigger = pat.get('trigger', [])
        module_name = pat.get('module')
        
        if not module_name:
            continue
            
        can_run = False
        if trigger:
            if all(t in parsed_data for t in trigger):
                can_run = True
            if 'hint' in parsed_data and 'hint' in trigger:
                can_run = True
        else:
            if 'ct_text' in parsed_data and 'classical' in module_name:
                can_run = True
                
        if can_run:
            mod_path = module_name.replace('.', '/') + '.py'
            if not os.path.exists(mod_path):
                continue
            # print(f"[*] Testing {name}...", flush=True)
                
            try:
                spec = importlib.util.spec_from_file_location("mod", mod_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                
                if hasattr(mod, 'solve'):
                    import inspect
                    sig = inspect.signature(mod.solve)
                    args_to_pass = []
                    missing_arg = False
                    for param in sig.parameters.values():
                        if param.kind == inspect.Parameter.VAR_KEYWORD:
                            continue
                        if param.name in parsed_data: 
                            args_to_pass.append(parsed_data[param.name])
                        elif param.name == 'filepath' and 'source_py' in parsed_data: 
                            args_to_pass.append(parsed_data['source_py'])
                        elif param.name == 'filepath' and 'filepath' in parsed_data:
                            args_to_pass.append(parsed_data['filepath'])
                        elif param.name == 'data': 
                            args_to_pass.append(parsed_data)
                        elif param.name == 'ct_text': 
                            args_to_pass.append(parsed_data.get('ct_text', ''))
                        elif param.name == 'c': 
                            args_to_pass.append(parsed_data.get('c'))
                        elif param.name == 'n': 
                            args_to_pass.append(parsed_data.get('n'))
                        elif param.name == 'e': 
                            args_to_pass.append(parsed_data.get('e'))
                        elif param.name == 'hint': 
                            args_to_pass.append(parsed_data.get('hint'))
                        elif param.default != inspect.Parameter.empty:
                            args_to_pass.append(param.default)
                        else: 
                            missing_arg = True; break
                            
                    if missing_arg: continue
                        
                    res = mod.solve(*args_to_pass)
                    if isinstance(res, str):
                        res = {'flag': res, 'method': name, 'detail': 'Solved'}
                    elif isinstance(res, bytes):
                        res = {'flag': res.decode('utf-8', errors='ignore'), 'method': name, 'detail': 'Solved'}
                    if res and isinstance(res, dict) and res.get('flag'):
                        flag_bytes = res['flag']
                        if isinstance(flag_bytes, str): flag_bytes = flag_bytes.encode()
                        
                        # BUG 1 FIX: Validasi format flag (misal: crypton{...}, picoCTF{...}, flag{...})
                        if flag_pattern.search(flag_bytes):
                            return res
                        
                        # Fallback cek printable format jika ada text "flag" atau setidaknya ada kurung kurawal
                        try:
                            if b'{' in flag_bytes and b'}' in flag_bytes:
                                printable = sum(1 for b in flag_bytes if 32 <= b <= 126 or b in (9, 10, 13))
                                if len(flag_bytes) > 0 and (printable / len(flag_bytes)) > 0.8:
                                    return res
                        except:
                            pass
            except Exception as e:
                print(f"[!] Error running solver {name}: {e}")
                
    return {"flag": None, "method": "dispatcher", "detail": "No pattern matched or no flag found"}
