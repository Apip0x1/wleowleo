from Crypto.Util.number import inverse, long_to_bytes
import re

def solve(p=None, g=None, A=None, B=None, c=None, data=None, **kwargs):
    """
    Solves ElGamal encryption when B == p - 1.
    If g is a quadratic non-residue, g^((p-1)/2) = -1 = p - 1 mod p, so d = (p-1)/2.
    """
    if isinstance(p, dict):
        data = p
    if data:
        p = data.get('p')
        g = data.get('g')
        A = data.get('A')
        B = data.get('B')
        c = data.get('c')
        raw_text = data.get('raw_text', '')
    else:
        raw_text = kwargs.get('raw_text', '')

    # Helper fallback from raw_text or ciphertext format
    if (not B or not c) and raw_text:
        nums = [int(x) for x in re.findall(r'\b[0-9]{20,}\b', raw_text)]
        if len(nums) >= 2 and not B:
            B = nums[0]
            c = nums[1]
    
    if raw_text and (not p or not A):
        p_match = re.search(r'\bp\s*[=:]\s*([0-9]+)', raw_text)
        if p_match: p = int(p_match.group(1))
        g_match = re.search(r'\bg\s*[=:]\s*([0-9]+)', raw_text)
        if g_match: g = int(g_match.group(1))
        A_match = re.search(r'\bA\s*[=:]\s*([0-9]+)', raw_text)
        if A_match: A = int(A_match.group(1))

    if not (p and A and B and c):
        return {"flag": None, "method": "elgamal_half_order", "detail": "Missing p, A, B, or c"}

    try:
        # Check if B == p - 1
        if B == p - 1:
            d = (p - 1) // 2
            k = pow(A, d, p)
            k_inv = inverse(k, p)
            m = (k_inv * c) % p
            flag = long_to_bytes(m)
            return {"flag": flag, "method": "elgamal_half_order", "detail": "Solved via Euler's criterion B == p - 1"}
        
        # Check if B == 1
        if B == 1:
            d = 0
            k = 1
            m = c % p
            flag = long_to_bytes(m)
            return {"flag": flag, "method": "elgamal_half_order", "detail": "Solved via trivial B == 1"}

        return {"flag": None, "method": "elgamal_half_order", "detail": "Condition B == p-1 not met"}
    except Exception as ex:
        return {"flag": None, "method": "elgamal_half_order", "detail": str(ex)}

if __name__ == "__main__":
    from Crypto.Util.number import getPrime, bytes_to_long
    # Test standalone with synthetic problem
    p_test = getPrime(512)
    g_test = 5
    d_test = (p_test - 1) // 2
    B_test = pow(g_test, d_test, p_test)
    assert B_test == p_test - 1 or B_test == 1
    if B_test == p_test - 1:
        msg = b"flag{test_elgamal_half_order}"
        m_int = bytes_to_long(msg)
        r_ephem = getPrime(256)
        A_test = pow(g_test, r_ephem, p_test)
        c_test = (m_int * pow(A_test, d_test, p_test)) % p_test
        res = solve(p=p_test, g=g_test, A=A_test, B=B_test, c=c_test)
        assert res["flag"] == msg, f"Failed: {res}"
        print("[PASS] Standalone synthetic test passed!")
    else:
        print("[PASS] (g is quadratic residue, test skipped safely)")
