def rational_to_contfrac(x, y):
    cf = []
    while y != 0:
        q = x // y
        cf.append(q)
        x, y = y, x - q * y
    return cf

def convergents_from_contfrac(frac):
    conv = []
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for a in frac:
        p = a * p1 + p0
        q = a * q1 + q0
        conv.append((p, q))
        p0, p1 = p1, p
        q0, q1 = q1, q
    return conv

def solve(n=None, e=None, c=None, c1=None, c2=None, a=None, g=None, max_seconds=3, **kwargs):
    if n is None or e is None:
        return {"flag": None, "method": "wiener_variant", "detail": "Missing n or e"}
    if e >= n:
        return {"flag": None, "method": "wiener_variant", "detail": "Wiener variant requires e < n"}
    import time
    t0 = time.time()
    try:
        sample_m = 12345
        sample_c = pow(sample_m, e, n)
        
        cf = rational_to_contfrac(e, n)
        conv = convergents_from_contfrac(cf)
        
        found_d = None
        q0 = 1
        prev_c_q = pow(sample_c, q0, n)
        
        for k, q1 in conv:
            if time.time() - t0 > max_seconds:
                break
            cur_c_q = pow(sample_c, q1, n)
            
            pow_cur = [1]
            for _ in range(1, 30):
                pow_cur.append((pow_cur[-1] * cur_c_q) % n)
                
            pow_prev = [1]
            for _ in range(1, 30):
                pow_prev.append((pow_prev[-1] * prev_c_q) % n)
                
            for r in range(30):
                val_r = pow_cur[r]
                for s in range(30):
                    if (val_r * pow_prev[s]) % n == sample_m:
                        cand_d = r * q1 + s * q0
                        if cand_d > 0 and pow(sample_c, cand_d, n) == sample_m:
                            found_d = cand_d
                            break
                if found_d: break
            if found_d: break
            q0 = q1
            prev_c_q = cur_c_q
            
        if not found_d:
            return {"flag": None, "method": "wiener_variant", "detail": "Variant Wiener failed to find d"}
            
        # Decrypt
        if c1 is not None and c2 is not None and a is not None and g is not None:
            k_val = pow(c1, found_d, n)
            K = pow(g, k_val, a)
            inv_K = pow(K, -1, a)
            m = (c2 * inv_K) % a
            from Crypto.Util.number import long_to_bytes
            return {"flag": long_to_bytes(m), "method": "wiener_variant", "detail": f"Decrypted hybrid ElGamal/RSA variant d={found_d}"}
            
        target_c = c if c is not None else c1
        if target_c is not None:
            m = pow(target_c, found_d, n)
            from Crypto.Util.number import long_to_bytes
            return {"flag": long_to_bytes(m), "method": "wiener_variant", "detail": f"Decrypted with d={found_d}"}
            
        return {"flag": None, "method": "wiener_variant", "detail": f"Found d={found_d} but missing ciphertext"}
    except Exception as ex:
        return {"flag": None, "method": "wiener_variant", "detail": str(ex)}
