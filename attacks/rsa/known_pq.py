def solve(data):
    try:
        p = data.get('p')
        q = data.get('q')
        e = data.get('e')
        c = data.get('c')
        n = data.get('n', p * q if p and q else None)
        
        if not (p and q and e and c and n):
            return {"flag": None, "method": "known_pq", "detail": "Missing parameters"}
            
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        
        flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        return {"flag": flag, "method": "known_pq", "detail": "Computed from given p and q"}
    except Exception as ex:
        return {"flag": None, "method": "known_pq", "detail": str(ex)}
