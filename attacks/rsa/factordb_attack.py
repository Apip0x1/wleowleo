import requests
import json

def solve(n, e, c):
    try:
        url = f"http://factordb.com/api?query={n}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        
        # Status 'FF' = Fully Factored
        # Status 'CF' = Composite, but completely factored? Actually 'CF' is composite factors, 'FF' is fully factored.
        if data.get('status') in ['FF']:
            factors = data.get('factors', [])
            phi = 1
            for f_str, count in factors:
                p = int(f_str)
                phi *= (p**(count - 1)) * (p - 1)
                
            try:
                d = pow(e, -1, phi)
                cur = c
                candidate_flag = None
                for round_num in range(1, 40):
                    cur = pow(cur, d, n)
                    cand = cur.to_bytes((cur.bit_length() + 7) // 8, 'big')
                    if round_num == 1:
                        candidate_flag = cand
                    import re
                    if re.search(rb'[A-Za-z0-9_]+\{[ -~]{3,100}\}', cand):
                        return {"flag": cand, "method": "factordb (INTERNET)", "detail": f"Decrypted after {round_num} rounds via FactorDB"}
                
                return {"flag": candidate_flag, "method": "factordb (INTERNET)", "detail": f"Found {sum(c for _, c in factors)} prime factors on FactorDB"}
            except Exception as e_dec:
                return {"flag": None, "method": "factordb (INTERNET)", "detail": f"Decryption failed: {e_dec}"}
        
        return {"flag": None, "method": "factordb", "detail": f"FactorDB status: {data.get('status')}"}
    except Exception as ex:
        return {"flag": None, "method": "factordb", "detail": str(ex)}
