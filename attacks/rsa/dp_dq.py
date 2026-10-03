import math
from Crypto.Util.number import inverse, long_to_bytes

def solve(n=None, e=None, c=None, dp=None, dq=None, **kwargs):
    if n is None or e is None or c is None:
        return {"flag": None, "method": "dp_dq", "detail": "Missing n, e, or c"}
    if dp is None and dq is None:
        return {"flag": None, "method": "dp_dq", "detail": "Missing dp and dq"}
        
    try:
        found_p = None
        # Attack with dp: e*dp - 1 = k*(p - 1) => p = (e*dp - 1)/k + 1
        if dp is not None:
            max_k = min(e, 100000)
            for k in range(1, max_k):
                if (e * dp - 1) % k == 0:
                    cand_p = (e * dp - 1) // k + 1
                    if cand_p > 1 and n % cand_p == 0:
                        found_p = cand_p
                        break
                        
        # Attack with dq: e*dq - 1 = k*(q - 1) => q = (e*dq - 1)/k + 1
        if not found_p and dq is not None:
            max_k = min(e, 100000)
            for k in range(1, max_k):
                if (e * dq - 1) % k == 0:
                    cand_q = (e * dq - 1) // k + 1
                    if cand_q > 1 and n % cand_q == 0:
                        found_p = cand_q
                        break
                        
        if found_p:
            p = found_p
            q = n // p
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            m = pow(c, d, n)
            flag = long_to_bytes(m)
            return {"flag": flag, "method": "dp_dq", "detail": "Factored n using CRT exponent"}
            
        return {"flag": None, "method": "dp_dq", "detail": "Failed to find p from dp/dq"}
    except Exception as ex:
        return {"flag": None, "method": "dp_dq", "detail": str(ex)}
