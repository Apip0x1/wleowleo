from Crypto.Util.number import long_to_bytes

def solve(n=None, d=None, c=None, data=None, **kwargs):
    """
    Direct RSA decryption with known private key exponent d and modulus n.
    """
    if isinstance(n, dict):
        data = n
    if data:
        n = data.get('n')
        d = data.get('d')
        c = data.get('c')
    else:
        if d is None: d = kwargs.get('d')
        if c is None: c = kwargs.get('c')
        if n is None: n = kwargs.get('n')

    if not (n and d and c):
        return {"flag": None, "method": "known_privatekey", "detail": "Missing n, d, or c"}

    try:
        m = pow(c, d, n)
        flag = long_to_bytes(m)
        return {"flag": flag, "method": "known_privatekey", "detail": "Decrypted with leaked private key d"}
    except Exception as ex:
        return {"flag": None, "method": "known_privatekey", "detail": str(ex)}

if __name__ == "__main__":
    from Crypto.Util.number import getPrime, bytes_to_long, inverse
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    e = 65537
    d = inverse(e, (p-1)*(q-1))
    test_flag = b"flag{test_known_privatekey}"
    c = pow(bytes_to_long(test_flag), e, n)
    res = solve(n=n, d=d, c=c)
    assert res["flag"] == test_flag, f"Failed: {res}"
    print("[PASS] Standalone test passed!")
