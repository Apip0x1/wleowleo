import math
import re
from Crypto.Util.number import inverse, long_to_bytes

def solve(n=None, e=None, c=None, s=None, hint=None, data=None, raw_text=None, **kwargs):
    if n is None or e is None or c is None:
        return {"flag": None, "method": "hint_gcd", "detail": "Missing n, e, or c"}
    
    val = s if s is not None else hint
    if val is None:
        return {"flag": None, "method": "hint_gcd", "detail": "Missing s or hint"}
        
    try:
        # Case 1: Direct GCD (e.g. s = p * phi or hint has factor of n)
        p = math.gcd(val, n)
        if 1 < p < n:
            q = n // p
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            m = pow(c, d, n)
            flag = long_to_bytes(m)
            return {"flag": flag, "method": "hint_gcd", "detail": f"Found factor p={p} via gcd(hint, n)"}
            
        # Case 2: Fermat Little Theorem leak: s = base^(p - offset) mod n
        text_to_search = raw_text or ""
        pow_leak = re.search(r'pow\s*\(\s*([0-9]+)\s*,\s*(?:p|q)\s*-\s*([0-9a-fx]+)', text_to_search, re.IGNORECASE)
        candidates = []
        if pow_leak:
            b_val = int(pow_leak.group(1), 0)
            off_val = int(pow_leak.group(2), 0)
            candidates.append((b_val, off_val))
            
        candidates.extend([(2, 0xdeadbeef), (2, 0x1337), (2, 0), (2, 1), (3, 0xdeadbeef)])
        for b_val, off_val in candidates:
            k = pow(b_val, off_val - 1, n)
            cand = (val * k - 1) % n
            p = math.gcd(cand, n)
            if 1 < p < n:
                q = n // p
                phi = (p - 1) * (q - 1)
                d = inverse(e, phi)
                m = pow(c, d, n)
                flag = long_to_bytes(m)
                return {"flag": flag, "method": "hint_gcd_fermat", "detail": f"Found factor via Fermat leak (base={b_val}, offset={hex(off_val)})"}
            
        return {"flag": None, "method": "hint_gcd", "detail": "gcd(val, n) and Fermat leak were trivial"}
    except Exception as ex:
        return {"flag": None, "method": "hint_gcd", "detail": str(ex)}
