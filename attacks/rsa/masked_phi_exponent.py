import math
import re
import ast
from Crypto.Util.number import long_to_bytes, inverse, isPrime
from Crypto.Cipher import AES

def solve(n=None, e=None, c=None, raw_text=None, filepath=None, **kwargs):
    """
    Solves RSA where the public exponent e is masked by a multiple of phi:
    e = e0 + k * phi
    Because phi = n - (p + q - 1) is very close to n,
    e / n gives an extremely accurate approximation of k:
    k = (e // n) + 1.
    From k, we recover e0 and p + q, factoring n in O(1) time.
    """
    if not n or not e or e <= n:
        return {"flag": None, "method": "masked_phi_exponent", "detail": "Requires e > n"}

    # k is approximately e / n
    base_k = e // n
    candidates_k = [base_k + 1, base_k, base_k + 2, base_k - 1]

    p, q, recovered_k = None, None, None
    for k in candidates_k:
        if k <= 0:
            continue
        R = k * n - e
        e0 = (-R) % k
        S = (R + e0) // k + 1  # S = p + q
        
        disc = S * S - 4 * n
        if disc >= 0:
            sqrt_disc = math.isqrt(disc)
            if sqrt_disc * sqrt_disc == disc:
                cand_p = (S + sqrt_disc) // 2
                cand_q = (S - sqrt_disc) // 2
                if cand_p > 1 and cand_q > 1 and cand_p * cand_q == n:
                    p, q = cand_p, cand_q
                    recovered_k = k
                    break

    if not p or not q:
        return {"flag": None, "method": "masked_phi_exponent", "detail": "Could not factor n"}

    phi = (p - 1) * (q - 1)
    
    # Decrypt if c is available
    if c:
        try:
            d = inverse(e, phi)
            m = pow(c, d, n)
            pt_bytes = long_to_bytes(m)
            
            # Check if pt_bytes directly contains flag
            flag_match = re.search(rb'[a-zA-Z0-9_]+\{[^}]+\}', pt_bytes)
            if flag_match:
                return {
                    "flag": flag_match.group(0),
                    "method": "masked_phi_exponent",
                    "detail": f"Decrypted directly from RSA with k={recovered_k}"
                }
                
            # If not direct flag, it might be an AES key (e.g. ticket/symmetric key)
            # Search for AES ciphertext and nonce/iv in raw_text or data
            text_sources = []
            if raw_text:
                text_sources.append(raw_text)
            if filepath:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        text_sources.append(f.read())
                except:
                    pass
                    
            full_text = "\n".join(text_sources)
            
            # Check for (enc_flag, nonce) tuple like enc_flag, nonce=(b'...', b'...')
            tuple_match = re.search(r'\((b[\'"][^\'"]+[\'"]),\s*(b[\'"][^\'"]+[\'"])\)', full_text)
            if tuple_match:
                try:
                    enc_data = ast.literal_eval(tuple_match.group(1))
                    nonce_data = ast.literal_eval(tuple_match.group(2))
                    
                    # Try AES CTR
                    for key_bytes in (pt_bytes, pt_bytes.ljust(16, b'\x00')[:16], pt_bytes.ljust(32, b'\x00')[:32]):
                        try:
                            cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce_data)
                            dec = cipher.decrypt(enc_data)
                            flag_match = re.search(rb'[a-zA-Z0-9_]+\{[^}]+\}', dec)
                            if flag_match:
                                return {
                                    "flag": flag_match.group(0),
                                    "method": "masked_phi_exponent",
                                    "detail": f"Decrypted AES-CTR with recovered RSA key (k={recovered_k})"
                                }
                        except:
                            pass
                except:
                    pass
                    
            # Try raw bytes as string if printable
            if all(32 <= b <= 126 or b in (10, 13) for b in pt_bytes):
                return {
                    "flag": pt_bytes,
                    "method": "masked_phi_exponent",
                    "detail": f"Printable plaintext from RSA with k={recovered_k}"
                }
        except Exception as e:
            pass

    return {
        "flag": None,
        "method": "masked_phi_exponent",
        "detail": f"Factored n (p={p}, q={q}) but failed to decrypt flag"
    }
