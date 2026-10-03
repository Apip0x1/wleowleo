import math
import random

def is_prime(n, k=5):
    if n < 2: return False
    if n in (2,3): return True
    if n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, min(n - 1, 1000000))
        x = pow(a, s, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

import time

def solve(n, e, c, max_seconds=2):
    try:
        t0 = time.time()
        a = 2
        for j in range(2, 100000):
            if j % 500 == 0 and (time.time() - t0) > max_seconds:
                return {"flag": None, "method": "pollard_pm1", "detail": f"Timeout (> {max_seconds}s)"}
            a = pow(a, j, n)
            p = math.gcd(a - 1, n)
            if 1 < p < n:
                q = n // p
                if p * q == n:
                    if not is_prime(p) or not is_prime(q):
                        return {"flag": None, "method": "pollard_pm1", "detail": f"Found factors p={p} but they are not prime!"}
                        
                    phi = (p-1)*(q-1)
                    d = pow(e, -1, phi)
                    m = pow(c, d, n)
                    return {"flag": m.to_bytes((m.bit_length() + 7) // 8, 'big'), "method": "pollard_pm1", "detail": f"p={p}"}
        return {"flag": None, "method": "pollard_pm1", "detail": "B bound reached"}
    except Exception as ex:
        return {"flag": None, "method": "pollard_pm1", "detail": str(ex)}
