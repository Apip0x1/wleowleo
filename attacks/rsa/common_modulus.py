import gmpy2
from Crypto.Util.number import long_to_bytes, GCD

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def neg_pow(a, b, n):
    # Calculates a^b mod n when b is negative
    inv = int(gmpy2.invert(a, n))
    return pow(inv, -b, n)

def solve(n, e1, c1, e2, c2):
    """
    Common Modulus attack.
    Works for gcd(e1, e2) == 1 and gcd(e1, e2) > 1 (when m^g < n).
    """
    try:
        g, a, b = egcd(e1, e2)
        
        if a < 0:
            c1_term = neg_pow(c1, a, n)
        else:
            c1_term = pow(c1, a, n)
            
        if b < 0:
            c2_term = neg_pow(c2, b, n)
        else:
            c2_term = pow(c2, b, n)
            
        ct = (c1_term * c2_term) % n
        
        if g == 1:
            m = ct
        else:
            root, exact = gmpy2.iroot(ct, g)
            m = int(root)
            
        flag = long_to_bytes(m)
        return {"flag": flag, "method": "common_modulus", "detail": f"gcd(e1,e2)={g}"}
    except Exception as ex:
        return {"flag": None, "method": "common_modulus", "detail": str(ex)}
