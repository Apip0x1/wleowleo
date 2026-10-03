import re
import base64

def parse_file(filepath):
    """
    Ekstrak berbagai variabel crypto dari file teks/python/PEM.
    Return dictionary berisi data yang berhasil diekstrak.
    """
    parsed = {}
    
    try:
        import os
        directory = os.path.dirname(filepath) or '.'
        data = ""
        # Read the main file first
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data += f.read() + "\n"
            
        # Also read sibling files if they are in a challenge subfolder (not root project dir)
        if directory not in ('.', ''):
            for sib in os.listdir(directory):
                sib_path = os.path.join(directory, sib)
                if sib_path != filepath and os.path.isfile(sib_path) and os.path.getsize(sib_path) < 100000:
                    with open(sib_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data += f"\n--- SIBLING FILE {sib} ---\n" + f.read() + "\n"
                    
        # Check for signature files and secret blob in directory
        if directory not in ('.', ''):
            sig1_path = os.path.join(directory, 'sig1.txt')
            sig2_path = os.path.join(directory, 'sig2.txt')
            if os.path.exists(sig1_path) and os.path.exists(sig2_path):
                t1 = open(sig1_path, 'r', errors='ignore').read()
                t2 = open(sig2_path, 'r', errors='ignore').read()
                m1_r = re.search(r'r\s*[=:]\s*([0-9a-fA-F]+)', t1)
                m1_s = re.search(r's\s*[=:]\s*([0-9a-fA-F]+)', t1)
                m1_z = re.search(r'(?:msg_hash|z|h)\s*[=:]\s*([0-9a-fA-F]+)', t1)
                m2_r = re.search(r'r\s*[=:]\s*([0-9a-fA-F]+)', t2)
                m2_s = re.search(r's\s*[=:]\s*([0-9a-fA-F]+)', t2)
                m2_z = re.search(r'(?:msg_hash|z|h)\s*[=:]\s*([0-9a-fA-F]+)', t2)
                if m1_r and m1_s and m1_z and m2_r and m2_s and m2_z:
                    parsed['r'] = int(m1_r.group(1), 16)
                    parsed['s1'] = int(m1_s.group(1), 16)
                    parsed['z1'] = int(m1_z.group(1), 16)
                    parsed['s2'] = int(m2_s.group(1), 16)
                    parsed['z2'] = int(m2_z.group(1), 16)

            blob_path = os.path.join(directory, 'secret_blob.bin')
            if os.path.exists(blob_path):
                parsed['secret_blob'] = open(blob_path, 'rb').read()

        parsed['raw_text'] = data
        # Check for JSON format (e.g. Edwards curve over reals / ECC parameters)
        if '{' in data and '"gx"' in data:
            try:
                import json
                j_match = re.search(r'\{[^{}]*"gx"[^{}]*\}', data, re.DOTALL)
                if j_match:
                    jdata = json.loads(j_match.group(0))
                    for k in ('gx', 'gy', 'px', 'py', 'ciphertext', 'iv'):
                        if k in jdata:
                            parsed[k] = jdata[k]
            except:
                pass

        parsed['filepath'] = filepath
        if filepath.endswith('.py'):
            parsed['source_py'] = filepath
            
        # 1. Parse Key-Value sederhana (misal: n = 1234, c: 0xabcd, hint = ...)
        # Format umum: var_name [=:] [b"|'|0x]? (value)
        patterns = {
            'n': r'\b(?:n|modulus)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'e': r'\b(?:e|pub_exp)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'c': r'\b(?:c|ct|ciphertext|enc|encrypted|enc_ticket)\b\s*[=:]\s*(0x[0-9a-fA-F]{2,}|[0-9a-fA-F]{2,})',
            'p': r'\b(?:p)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'q': r'\b(?:q)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'hint': r'\b(?:hint)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            's': r'\b(?:s)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'dp': r'\b(?:dp)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'dq': r'\b(?:dq)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'e1': r'\b(?:e1)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'e2': r'\b(?:e2)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'c1': r'\b(?:c1)\b\s*[=:]\s*(0x[0-9a-fA-F]{2,}|[0-9a-fA-F]{2,})',
            'c2': r'\b(?:c2)\b\s*[=:]\s*(0x[0-9a-fA-F]{2,}|[0-9a-fA-F]{2,})',
            'd': r'\b(?:d|priv_exp)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'g': r'\b(?:g)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'A': r'\b(?:A)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)',
            'B': r'\b(?:B)\b\s*[=:]\s*(0x[0-9a-fA-F]+|[0-9]+)'
        }
        
        # Check for pubkey tuple, e.g. pubkey = (n, e, ...) or (n, e)
        pubkey_tuple_match = re.search(r'\bpubkey\s*[=:]\s*\(([^)]+)\)', data)
        if pubkey_tuple_match:
            try:
                parts = [int(x.strip().rstrip('L'), 16 if x.strip().startswith('0x') else 10) for x in pubkey_tuple_match.group(1).split(',') if x.strip()]
                if len(parts) >= 2:
                    if 'n' not in parsed: parsed['n'] = parts[0]
                    if 'e' not in parsed: parsed['e'] = parts[1]
                if len(parts) >= 4:
                    if 'a' not in parsed: parsed['a'] = parts[2]
                    if 'g' not in parsed: parsed['g'] = parts[3]
            except:
                pass

        # Check for c tuple, e.g. c = (c1, c2)
        c_tuple_match = re.search(r'\bc\s*[=:]\s*\(([^)]+)\)', data)
        if c_tuple_match:
            try:
                parts = [int(x.strip().rstrip('L'), 16 if x.strip().startswith('0x') else 10) for x in c_tuple_match.group(1).split(',') if x.strip()]
                if len(parts) >= 2:
                    if 'c1' not in parsed: parsed['c1'] = parts[0]
                    if 'c2' not in parsed: parsed['c2'] = parts[1]
                    if 'c' not in parsed: parsed['c'] = parts[0]
            except:
                pass

        # Check for encryption_keys = [...]
        keys_match = re.search(r'encryption_keys\s*[=:]\s*(\[[^\]]+\])', data)
        if keys_match:
            try:
                import ast
                raw_keys = ast.literal_eval(keys_match.group(1).replace('L', ''))
                e_prod = 1
                for k in raw_keys:
                    e_prod *= int(k)
                parsed['e'] = e_prod
            except:
                pass

        # Check for arithmetic expressions like e = 2**16 + 1 or 65537
        e_expr_match = re.search(r'\b(?:e|E|pub_exp)\s*[=:]\s*([0-9\s\*\+\-\^]+)', data)
        if e_expr_match and 'e' not in parsed:
            expr_str = e_expr_match.group(1).split('\n')[0].strip()
            # If safe arithmetic expr
            if re.match(r'^[0-9\s\*\+\-\(\)]+$', expr_str) and ('**' in expr_str or '+' in expr_str or '*' in expr_str):
                try:
                    parsed['e'] = eval(expr_str, {"__builtins__": None}, {})
                except:
                    pass

        for key, pat in patterns.items():
            if key in parsed and key == 'e':
                continue
            match = re.search(pat, data, re.IGNORECASE)
            if match:
                val = match.group(1)
                try:
                    if val.startswith('0x') or (key in ('c', 'c1', 'c2') and any(ch in 'abcdefABCDEF' for ch in val)):
                        parsed[key] = int(val, 16)
                    else:
                        parsed[key] = int(val)
                except:
                    pass
                    
        # 2. Parse PEM Public Key jika ada
        if '-----BEGIN PUBLIC KEY-----' in data or '-----BEGIN RSA PUBLIC KEY-----' in data:
            pem_match = re.search(r'-----BEGIN (?:RSA )?PUBLIC KEY-----.*?-----END (?:RSA )?PUBLIC KEY-----', data, re.DOTALL)
            if pem_match:
                pem_str = pem_match.group(0)
                try:
                    from Crypto.PublicKey import RSA
                    key = RSA.importKey(pem_str)
                    parsed['n'] = key.n
                    parsed['e'] = key.e
                except:
                    try:
                        from ecdsa import VerifyingKey
                        vk = VerifyingKey.from_pem(pem_str.encode())
                        parsed['curve_order'] = vk.curve.order
                    except:
                        pass
                
        # 3. Parse pure hex string as c if c is not explicitly labeled
        hex_blocks = re.findall(r'\b(?:[0-9a-fA-F]{64,})\b', data)
        if 'c' not in parsed:
            known_str_vals = set(str(v) for v in parsed.values() if isinstance(v, int))
            pure_hex = [h for h in hex_blocks if h not in known_str_vals]
            with_alpha = [h for h in pure_hex if re.search(r'[a-fA-F]', h)]
            if with_alpha:
                parsed['c'] = int(with_alpha[0], 16)
            elif pure_hex:
                parsed['c'] = int(pure_hex[0], 16)

        # 4.0 Parse list of modulus and list of ciphertexts / e
        num_lines = [l.strip() for l in data.splitlines() if l.strip() and l.strip().isdigit()]
        if len(num_lines) >= 12 and len(num_lines) % 4 == 0:
            parsed['a_list'] = [int(num_lines[i]) for i in range(0, len(num_lines), 4)]
            parsed['b_list'] = [int(num_lines[i+1]) for i in range(0, len(num_lines), 4)]
            parsed['ciphertext_list'] = [int(num_lines[i+2]) for i in range(0, len(num_lines), 4)]
            parsed['modulus_list'] = [int(num_lines[i+3]) for i in range(0, len(num_lines), 4)]
            if 'e' not in parsed:
                parsed['e'] = len(parsed['modulus_list'])

        # 4. Fallback: Parse angka acak besar sebagai n dan c jika belum ketemu
        if ('n' not in parsed or 'c' not in parsed) and 'modulus_list' not in parsed:
            big_nums = re.findall(r'\b[1-9][0-9]{50,}\b', data)
            known_vals = set([v for k,v in parsed.items() if isinstance(v, int)])
            big_nums = [int(x) for x in big_nums if int(x) not in known_vals]
            if len(big_nums) >= 2:
                big_nums = sorted(big_nums, reverse=True)
                if 'n' not in parsed: parsed['n'] = big_nums[0]
                if 'c' not in parsed: parsed['c'] = big_nums[1]
            elif len(big_nums) == 1:
                if 'n' not in parsed: parsed['n'] = big_nums[0]
        # 4.5 Parse Base64 sebagai Ciphertext jika c belum ada dan ada blok base64
        if 'c' not in parsed:
            search_text = data
            if '-----END PUBLIC KEY-----' in data:
                search_text = data.split('-----END PUBLIC KEY-----')[1]
            elif '-----END RSA PUBLIC KEY-----' in data:
                search_text = data.split('-----END RSA PUBLIC KEY-----')[1]
                
            b64_blocks = re.findall(r'(?:[A-Za-z0-9+/]{4}[\r\n\s]*){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})?', search_text)
            for block in b64_blocks:
                clean_block = re.sub(r'\s+', '', block)
                if 'MIIB' not in clean_block and len(clean_block) >= 32:
                    try:
                        decoded = base64.b64decode(clean_block)
                        if len(decoded) >= 16:
                            parsed['c'] = int.from_bytes(decoded, 'big')
                            break
                    except:
                        pass

        if 'modulus_list' in data:
            m_list_match = re.search(r'modulus_list\s*[=:]\s*(\[[^\]]+\])', data)
            if m_list_match:
                try:
                    raw_list_str = m_list_match.group(1).replace('L', '')
                    import ast
                    parsed['modulus_list'] = [int(x) for x in ast.literal_eval(raw_list_str)]
                except:
                    pass
        
        # Parse e list if present
        e_list_match = re.search(r'\be\s*[=:]\s*(\[[^\]]+\])', data)
        if e_list_match:
            try:
                raw_e_str = e_list_match.group(1).replace('L', '')
                import ast
                parsed['e_list'] = [int(x) for x in ast.literal_eval(raw_e_str)]
            except:
                pass
                
        # Parse ciphertext list if present
        c_list_match = re.search(r'(\[\s*(?:\'[0-9a-fA-F]+\'|\"[0-9a-fA-F]+\"|[0-9]+)\s*(?:,\s*(?:\'[0-9a-fA-F]+\'|\"[0-9a-fA-F]+\"|[0-9]+)\s*)+\])', data)
        if c_list_match and 'ciphertext_list' not in parsed:
            try:
                import ast
                raw_c_list = ast.literal_eval(c_list_match.group(1))
                parsed['ciphertext_list'] = [int(x, 16) if isinstance(x, str) and not x.isdigit() else int(x) for x in raw_c_list]
            except:
                pass

        # 5. Fallback klasik untuk teks ciphertext ASCII string
        if 'c' not in parsed and not filepath.endswith('.py'):
            parsed['ct_text'] = data.strip()
            
    except Exception as e:
        print(f"[!] Parser Error: {e}")
        
    return parsed

