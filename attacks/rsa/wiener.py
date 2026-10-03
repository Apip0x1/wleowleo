def rational_to_contfrac(x, y):
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac):
    convs = []
    for i in range(len(frac)):
        if i == 0:
            ni, di = frac[0], 1
        elif i == 1:
            ni, di = frac[0]*frac[1] + 1, frac[1]
        else:
            ni = frac[i]*convs[i-1][0] + convs[i-2][0]
            di = frac[i]*convs[i-1][1] + convs[i-2][1]
        convs.append((ni, di))
    return convs

def solve(n, e, c):
    try:
        frac = rational_to_contfrac(e, n)
        convs = convergents_from_contfrac(frac)
        for k, d in convs:
            if k == 0 or d % 2 == 0: continue
            if (e * d - 1) % k != 0: continue
            phi = (e * d - 1) // k
            # Method 1: Check roots x^2 - (n - phi + 1)x + n = 0
            b = n - phi + 1
            disc = b*b - 4*n
            if disc >= 0:
                from math import isqrt
                s = isqrt(disc)
                if s*s == disc:
                    m = pow(c, d, n)
                    return {"flag": m.to_bytes((m.bit_length() + 7) // 8, 'big'), "method": "wiener", "detail": f"Found d={d}"}
            
            # Method 2: Direct test with sample plaintext
            sample_m = 12345
            sample_c = pow(sample_m, e, n)
            if pow(sample_c, d, n) == sample_m:
                m = pow(c, d, n)
                return {"flag": m.to_bytes((m.bit_length() + 7) // 8, 'big'), "method": "wiener", "detail": f"Found d={d} via sample test"}

        return {"flag": None, "method": "wiener", "detail": "Wiener failed"}
    except Exception as ex:
        return {"flag": None, "method": "wiener", "detail": str(ex)}
