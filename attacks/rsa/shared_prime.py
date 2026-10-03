import math
from Crypto.Util.number import inverse, long_to_bytes
from sympy.ntheory.residue_ntheory import sqrt_mod

def solve(modulus_list=None, e_list=None, ciphertext_list=None, data=None, **kwargs):
    """
    Solves shared prime across multiple moduli (batch GCD / pairwise GCD).
    Handles coprime exponents and even exponents (via modular square root CRT).
    """
    if isinstance(modulus_list, dict):
        data = modulus_list
    if data:
        modulus_list = data.get('modulus_list')
        e_list = data.get('e_list')
        ciphertext_list = data.get('ciphertext_list')

    if not modulus_list:
        return {"flag": None, "method": "shared_prime", "detail": "Missing modulus_list"}

    n_count = len(modulus_list)
    try:
        for i in range(n_count):
            for j in range(i + 1, n_count):
                n1 = modulus_list[i]
                n2 = modulus_list[j]
                p = math.gcd(n1, n2)
                if 1 < p < n1:
                    q = n1 // p
                    phi = (p - 1) * (q - 1)
                    
                    e = e_list[i] if (e_list and len(e_list) > i) else 65537
                    c = ciphertext_list[i] if (ciphertext_list and len(ciphertext_list) > i) else None
                    
                    if c is None:
                        continue
                        
                    # Case 1: gcd(e, phi) == 1
                    if math.gcd(e, phi) == 1:
                        d = inverse(e, phi)
                        m = pow(c, d, n1)
                        flag = long_to_bytes(m)
                        return {"flag": flag, "method": "shared_prime", "detail": f"Shared factor between {i} and {j}"}

                    # Case 2: gcd(e, phi) == 2 (even e)
                    if math.gcd(e, phi) == 2 and e % 2 == 0:
                        e_prime = e // 2
                        if math.gcd(e_prime, phi) == 1:
                            d = inverse(e_prime, phi)
                            m2 = pow(c, d, n1)
                            r_p = sqrt_mod(m2 % p, p, all_roots=True)
                            r_q = sqrt_mod(m2 % q, q, all_roots=True)
                            inv_q = inverse(q, p)
                            for mp in r_p:
                                for mq in r_q:
                                    m = (mq + q * ((mp - mq) * inv_q % p)) % n1
                                    cand = long_to_bytes(m)
                                    if b'{' in cand and b'}' in cand:
                                        return {"flag": cand, "method": "shared_prime", "detail": f"Shared prime + sqrt_mod on {i} and {j}"}

        return {"flag": None, "method": "shared_prime", "detail": "No shared factors found or cannot invert"}
    except Exception as ex:
        return {"flag": None, "method": "shared_prime", "detail": str(ex)}

if __name__ == "__main__":
    from Crypto.Util.number import getPrime, bytes_to_long
    p = getPrime(256)
    q1 = getPrime(256)
    q2 = getPrime(256)
    n1 = p * q1
    n2 = p * q2
    e = 65537
    flag = b"flag{test_shared_prime}"
    c1 = pow(bytes_to_long(flag), e, n1)
    res = solve(modulus_list=[n1, n2], e_list=[e, e], ciphertext_list=[c1, 0])
    assert res["flag"] == flag, f"Failed: {res}"
    print("[PASS] Standalone test passed!")
