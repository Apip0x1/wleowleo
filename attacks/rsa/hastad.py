from Crypto.Util.number import GCD, long_to_bytes
import gmpy2

def crt(list_a, list_m):
    """
    Chinese Remainder Theorem for coprime moduli list_m.
    """
    try:
        assert len(list_a) == len(list_m)
        M = 1
        for m in list_m:
            M *= m
        x = 0
        for a_i, m_i in zip(list_a, list_m):
            b_i = M // m_i
            b_inv = int(gmpy2.invert(b_i, m_i))
            x = (x + a_i * b_i * b_inv) % M
        return x, M
    except Exception:
        return None, None

def solve(modulus_list=None, ciphertext_list=None, e=None, data=None, **kwargs):
    """
    Standard Hastad Broadcast attack for unpadded identical message m encrypted
    under multiple coprime moduli N_i with same public exponent e.
    m^e = CRT(c_i, N_i). Then integer e-th root gives m.
    """
    if isinstance(modulus_list, dict):
        data = modulus_list
    if data:
        modulus_list = data.get('modulus_list')
        ciphertext_list = data.get('ciphertext_list')
        e = data.get('e', 3)
    else:
        if e is None: e = kwargs.get('e', 3)
        if modulus_list is None: modulus_list = kwargs.get('modulus_list')
        if ciphertext_list is None: ciphertext_list = kwargs.get('ciphertext_list')

    if not (modulus_list and ciphertext_list and len(modulus_list) >= e and len(ciphertext_list) >= e):
        return {"flag": None, "method": "hastad_broadcast", "detail": f"Need at least {e} moduli and ciphertexts"}

    try:
        selected_c = ciphertext_list[:e]
        selected_n = modulus_list[:e]
        
        c_crt, n_crt = crt(selected_c, selected_n)
        if c_crt is None:
            return {"flag": None, "method": "hastad_broadcast", "detail": "CRT failed (moduli not coprime?)"}

        root, exact = gmpy2.iroot(c_crt, e)
        if exact:
            m = int(root)
            flag = long_to_bytes(m)
            return {"flag": flag, "method": "hastad_broadcast", "detail": f"Exact root with {e} ciphertexts"}

        # Check for linear padding Hastad (ai, bi, ci, ni) pattern
        raw_text = (data or {}).get('raw_text', '') if isinstance(data, dict) else kwargs.get('raw_text', '')
        if raw_text:
            lines = [l.strip() for l in raw_text.splitlines() if l.strip() and l.strip().isdigit()]
            if len(lines) >= 12 and len(lines) % 4 == 0:
                import subprocess, os
                sage_path = "/home/apip/miniforge3/envs/sage_env/bin/sage"
                script_path = os.path.join(os.path.dirname(__file__), "..", "lattice", "hastad_linear.sage")
                if os.path.exists(sage_path) and os.path.exists(script_path):
                    proc = subprocess.run([sage_path, script_path], capture_output=True, text=True, timeout=60)
                    for line in proc.stdout.splitlines():
                        if "FLAG FOUND:" in line:
                            flag_val = line.split("FLAG FOUND:")[1].strip()
                            return {"flag": flag_val.encode(), "method": "hastad_linear", "detail": "Solved via Sage Coppersmith"}

        return {"flag": None, "method": "hastad_broadcast", "detail": "Integer root was not exact (padded/linear?)"}
    except Exception as ex:
        return {"flag": None, "method": "hastad_broadcast", "detail": str(ex)}

if __name__ == "__main__":
    from Crypto.Util.number import getPrime, bytes_to_long
    e_val = 3
    test_flag = b"flag{test_hastad_broadcast}"
    m_val = bytes_to_long(test_flag)
    mod_list = [getPrime(512) * getPrime(512) for _ in range(e_val)]
    c_list = [pow(m_val, e_val, n_i) for n_i in mod_list]
    res = solve(modulus_list=mod_list, ciphertext_list=c_list, e=e_val)
    assert res["flag"] == test_flag, f"Failed: {res}"
    print("[PASS] Hastad broadcast standalone test passed!")
