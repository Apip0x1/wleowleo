import gmpy2
from Crypto.Util.number import long_to_bytes

def solve(n=None, e=None, c=None, data=None, **kwargs):
    """
    Solves RSA with small e (e.g., e=3, 5) without padding (m^e < n, or small k where m^e = c + k*n).
    """
    if isinstance(n, dict):
        data = n
    if data:
        n = data.get('n')
        e = data.get('e')
        c = data.get('c')
    else:
        if n is None: n = kwargs.get('n')
        if e is None: e = kwargs.get('e')
        if c is None: c = kwargs.get('c')

    if not (e and c):
        return {"flag": None, "method": "small_e", "detail": "Missing e or c"}

    try:
        # 1. Direct e-th root when m^e < n
        root, exact = gmpy2.iroot(c, e)
        if exact:
            flag = long_to_bytes(int(root))
            return {"flag": flag, "method": "small_e", "detail": f"Exact {e}-th root (m^{e} < n)"}

        # 2. Check small k if n is provided (c + k*n) for small k up to 100000
        if n:
            for k in range(1, 100000):
                root, exact = gmpy2.iroot(c + k * n, e)
                if exact:
                    flag = long_to_bytes(int(root))
                    return {"flag": flag, "method": "small_e", "detail": f"Unpadded small e with k={k}"}

        return {"flag": None, "method": "small_e", "detail": "No exact root found"}
    except Exception as ex:
        return {"flag": None, "method": "small_e", "detail": str(ex)}

if __name__ == "__main__":
    from Crypto.Util.number import bytes_to_long, getPrime
    test_flag = b"flag{test_small_e_root}"
    m = bytes_to_long(test_flag)
    e = 3
    c = pow(m, e)
    res = solve(e=e, c=c)
    assert res["flag"] == test_flag, f"Failed: {res}"
    print("[PASS] Standalone test passed!")
