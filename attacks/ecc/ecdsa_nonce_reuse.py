import os
import re
import string
import base64
from hashlib import sha256
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import AES
import ecdsa

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
NIST256P_N = ecdsa.NIST256p.order

def solve(filepath=None, data=None, raw_text=None, **kwargs):
    """
    Solves ECDSA nonce reuse vulnerability when two signatures share the same r.
    Supports:
    1. Multiple signatures in a single log/output file (e.g. Record <tag> [h, r, s]).
    2. Separate sig1.txt / sig2.txt files.
    """
    try:
        target_dir = None
        full_text = raw_text or ""
        
        if filepath and os.path.exists(filepath):
            target_dir = os.path.dirname(filepath) if os.path.isfile(filepath) else filepath
            if not full_text and os.path.isfile(filepath):
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        full_text = f.read()
                except:
                    pass
        elif data and isinstance(data, dict):
            fp = data.get('filepath')
            if fp and os.path.exists(fp):
                target_dir = os.path.dirname(fp)
            if not full_text:
                full_text = data.get('raw_text', '')

        # Check target_dir and parent directory for context files (chall.py, description.txt, etc.)
        dirs_to_check = []
        if target_dir and os.path.exists(target_dir):
            dirs_to_check.append(target_dir)
            parent = os.path.dirname(target_dir)
            if parent and parent != target_dir and os.path.exists(parent):
                dirs_to_check.append(parent)

        for d in dirs_to_check:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                if fpath != filepath and os.path.isfile(fpath) and fname.endswith(('.txt', '.py', '.log', '.md', '.html')):
                    try:
                        with open(fpath, 'r', errors='ignore') as sf:
                            full_text += "\n" + sf.read()
                    except:
                        pass

        # Case A: Check for Record <tag> [ h, r, s ] format in single file
        record_matches = re.findall(r'Record\s+([0-9a-fA-F]+)\s*\[([0-9a-fA-F]+),\s*([0-9a-fA-F]+),\s*([0-9a-fA-F]+)\]', full_text)
        if record_matches:
            by_r = {}
            dup_pair = None
            for tag, h, r, s in record_matches:
                if r in by_r and by_r[r][3] != s:
                    dup_pair = (by_r[r], (tag, h, r, s))
                    break
                by_r[r] = (tag, h, r, s)

            if dup_pair:
                (tag1, h1, r1, s1), (tag2, h2, r2, s2) = dup_pair
                r_val = int(r1, 16)
                s1_val = int(s1, 16)
                s2_val = int(s2, 16)
                
                # Check curve order
                n_curve = SECP256K1_N if (r_val < SECP256K1_N) else NIST256P_N
                
                # Check if tag is base64
                i1, i2 = None, None
                try:
                    i1 = base64.b64decode(bytes.fromhex(tag1)).decode()
                    i2 = base64.b64decode(bytes.fromhex(tag2)).decode()
                except:
                    pass

                # Check if msg template exists in full_text
                # e.g. `log-####: event stream entry #i`
                tmpl_match = re.search(r'`([^`]*####[^`]*)`', full_text)
                
                # Check salt from source code hashlib.sha256(m + b"...") or "67 is lucky"
                salt = b""
                hash_salt_m = re.search(r'hashlib\.sha256\(\w+\s*\+\s*b["\']([^"\']+)["\']\)', full_text)
                if hash_salt_m:
                    salt = hash_salt_m.group(1).encode()
                else:
                    lucky_match = re.search(r'[\u201c\u201d"\'‘]([0-9a-zA-Z_]+)[\u201c\u201d"\'’]\s*is lucky', full_text)
                    if lucky_match:
                        salt = lucky_match.group(1).encode()

                z1, z2 = None, None
                if tmpl_match and i1 and i2:
                    tmpl = tmpl_match.group(1)
                    target1_bytes = bytes.fromhex(h1)
                    target2_bytes = bytes.fromhex(h2)
                    
                    # Brute force 4 digits
                    for d1 in string.digits:
                        for d2 in string.digits:
                            for d3 in string.digits:
                                for d4 in string.digits:
                                    code = f"{d1}{d2}{d3}{d4}"
                                    if not z1:
                                        m_cand = tmpl.replace('####', code).replace('#i', f"#{i1}").encode()
                                        if sha256(m_cand).digest() == target1_bytes:
                                            z1 = int.from_bytes(sha256(m_cand + salt).digest(), 'big')
                                    if not z2:
                                        m_cand = tmpl.replace('####', code).replace('#i', f"#{i2}").encode()
                                        if sha256(m_cand).digest() == target2_bytes:
                                            z2 = int.from_bytes(sha256(m_cand + salt).digest(), 'big')
                                    if z1 and z2: break
                                if z1 and z2: break
                            if z1 and z2: break
                        if z1 and z2: break

                if not z1 or not z2:
                    z1 = int(h1, 16)
                    z2 = int(h2, 16)

                curve_orders = [SECP256K1_N, NIST256P_N]
                if kwargs.get('n'):
                    curve_orders.insert(0, kwargs['n'])

                for n_curve in curve_orders:
                    try:
                        k = ((z1 - z2) * inverse((s1_val - s2_val) % n_curve, n_curve)) % n_curve
                        d = (((s1_val * k) - z1) * inverse(r_val, n_curve)) % n_curve

                        # Look for encrypted_flag
                        enc_flag_m = re.search(r'encrypted_flag\s*=\s*([0-9a-fA-F]+)', full_text)
                        if enc_flag_m:
                            enc_blob = bytes.fromhex(enc_flag_m.group(1))
                            key = sha256(long_to_bytes(d, 32)).digest()
                            for mode in (AES.MODE_ECB, AES.MODE_CBC):
                                try:
                                    cipher = AES.new(key, mode)
                                    dec = cipher.decrypt(enc_blob)
                                    flag_m = re.search(rb'[a-zA-Z0-9_]+\{[^}]+\}', dec)
                                    if flag_m:
                                        return {
                                            "flag": flag_m.group(0),
                                            "method": "ecdsa_nonce_reuse",
                                            "detail": f"Recovered d={hex(d)} and decrypted encrypted_flag"
                                        }
                                except:
                                    pass
                    except:
                        pass

        # Case B: Separate signature files (sig1.txt, sig2.txt)
        if target_dir and os.path.exists(target_dir):
            files = os.listdir(target_dir)
            sig_files = sorted([f for f in files if 'sig' in f.lower() and f.endswith('.txt')])
            if len(sig_files) >= 2:
                n = None
                for f in files:
                    if f.endswith('.pem') or f.endswith('.pub'):
                        try:
                            with open(os.path.join(target_dir, f), 'rb') as pf:
                                vk = ecdsa.VerifyingKey.from_pem(pf.read())
                                n = vk.curve.order
                                break
                        except:
                            pass

                if not n:
                    n = ecdsa.NIST256p.order

                sigs = []
                for sf in sig_files[:2]:
                    content = open(os.path.join(target_dir, sf)).read()
                    r_m = re.search(r'\br\s*[:=]\s*([0-9a-fA-F]+)', content)
                    s_m = re.search(r'\bs\s*[:=]\s*([0-9a-fA-F]+)', content)
                    z_m = re.search(r'\b(?:msg_hash|hash|z)\s*[:=]\s*([0-9a-fA-F]+)', content)
                    if r_m and s_m and z_m:
                        sigs.append((int(r_m.group(1), 16), int(s_m.group(1), 16), int(z_m.group(1), 16)))

                if len(sigs) >= 2:
                    (r1, s1, z1), (r2, s2, z2) = sigs[0], sigs[1]
                    if r1 == r2:
                        r = r1
                        k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
                        d = (((s1 * k) - z1) * pow(r, -1, n)) % n

                        blob_files = [f for f in files if 'secret' in f.lower() or 'blob' in f.lower() or 'cipher' in f.lower() or f.endswith('.bin')]
                        if blob_files:
                            with open(os.path.join(target_dir, blob_files[0]), 'rb') as bf:
                                blob = bf.read()

                            seed = long_to_bytes(d, 32)
                            keystream = b""
                            counter = 0
                            while len(keystream) < len(blob):
                                keystream += sha256(seed + counter.to_bytes(4, 'big')).digest()
                                counter += 1
                            
                            flag = bytes([b ^ k_b for b, k_b in zip(blob, keystream)])
                            if b'{' in flag and b'}' in flag:
                                return {"flag": flag, "method": "ecdsa_nonce_reuse", "detail": f"Recovered private key d and decrypted {blob_files[0]}"}

                            key = sha256(seed).digest()
                            for mode in (AES.MODE_ECB,):
                                try:
                                    cipher = AES.new(key, mode)
                                    dec = cipher.decrypt(blob)
                                    if b'{' in dec and b'}' in dec:
                                        return {"flag": dec, "method": "ecdsa_nonce_reuse", "detail": "Decrypted with AES(SHA256(d))"}
                                except:
                                    pass

        return {"flag": None, "method": "ecdsa_nonce_reuse", "detail": "No nonce reuse match found"}
    except Exception as ex:
        return {"flag": None, "method": "ecdsa_nonce_reuse", "detail": str(ex)}
