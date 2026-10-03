import os

def solve(filepath=None, data=None, **kwargs):
    """
    Solves stream cipher where keystream_leak or PRNG internal states are given in a sibling file.
    XORs ciphertext bytes with lowest byte of leaked states or raw keystream bytes.
    """
    try:
        raw_ct = None
        target_dir = None
        
        if filepath and os.path.exists(filepath):
            target_dir = os.path.dirname(filepath)
            if not os.path.isdir(filepath):
                with open(filepath, 'rb') as f:
                    raw_ct = f.read()
        elif data and isinstance(data, dict):
            raw_text = data.get('raw_text', '')
            # Try to get ciphertext bytes
            if 'c' in data:
                c_val = data['c']
                if isinstance(c_val, int):
                    raw_ct = c_val.to_bytes((c_val.bit_length() + 7) // 8, 'big')
        
        if not target_dir and filepath:
            target_dir = os.path.dirname(filepath)
            
        if not target_dir:
            return {"flag": None, "method": "keystream_leak", "detail": "No directory context"}

        # Search for leak files in directory
        leak_files = [f for f in os.listdir(target_dir) if 'leak' in f.lower() or 'state' in f.lower() or 'key' in f.lower()]
        ct_files = [f for f in os.listdir(target_dir) if 'cipher' in f.lower() or 'enc' in f.lower() or 'ct' in f.lower() or f.endswith('.bin')]

        if not raw_ct and ct_files:
            ct_path = os.path.join(target_dir, ct_files[0])
            with open(ct_path, 'rb') as f:
                raw_ct = f.read()

        if not raw_ct:
            return {"flag": None, "method": "keystream_leak", "detail": "Missing ciphertext bytes"}

        for lf in leak_files:
            lpath = os.path.join(target_dir, lf)
            if not os.path.isfile(lpath) or lpath == filepath:
                continue
            with open(lpath, 'r', errors='ignore') as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
            
            # Case 1: Integer states per line (e.g. state & 0xFF)
            int_states = []
            for l in lines:
                try:
                    int_states.append(int(l, 0))
                except:
                    pass
            
            if int_states:
                # Variant A: state & 0xFF
                ks = bytes([s & 0xFF for s in int_states])
                flag = bytes([c ^ k for c, k in zip(raw_ct, ks)])
                if b'{' in flag and b'}' in flag:
                    return {"flag": flag, "method": "keystream_leak", "detail": f"Decrypted with state & 0xFF from {lf}"}

                # Variant B: raw big/little endian bytes of states
                ks_be = b''.join([s.to_bytes(4, 'big') for s in int_states])
                flag = bytes([c ^ k for c, k in zip(raw_ct, ks_be)])
                if b'{' in flag and b'}' in flag:
                    return {"flag": flag, "method": "keystream_leak", "detail": f"Decrypted with state bytes from {lf}"}

        return {"flag": None, "method": "keystream_leak", "detail": "Keystream leak could not decrypt flag"}
    except Exception as ex:
        return {"flag": None, "method": "keystream_leak", "detail": str(ex)}
