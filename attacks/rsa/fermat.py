import math
from math import isqrt
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
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

import time

def get_factors_fermat(n, limit=20000, max_seconds=3):
    t0 = time.time()
    a = isqrt(n)
    if a * a == n:
        return a, a
    a += 1
    b2 = a * a - n
    steps = 0
    while steps < limit:
        if steps % 1000 == 0 and (time.time() - t0) > max_seconds:
            break
        s = isqrt(b2)
        if s * s == b2:
            return a - s, a + s
        a += 1
        b2 = a * a - n
        steps += 1
    return None, None

def get_all_prime_factors(n, depth=0):
    if depth > 10:
        return [n]
    if is_prime(n):
        return [n]
    p, q = get_factors_fermat(n)
    if p and q:
        return get_all_prime_factors(p, depth+1) + get_all_prime_factors(q, depth+1)
    return [n] # Cannot factor further with Fermat

def solve(n, e, c):
    try:
        factors = get_all_prime_factors(n)
        if len(factors) > 1 and all(is_prime(f) for f in factors):
            # We found all prime factors!
            phi = 1
            for f in factors:
                phi *= (f - 1)
            
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            
            detail = f"Found {len(factors)} factors via Fermat."
            return {"flag": flag, "method": "fermat_recursive", "detail": detail}
        
        return {"flag": None, "method": "fermat", "detail": "Not completely factored by Fermat"}
    except Exception as ex:
        return {"flag": None, "method": "fermat", "detail": str(ex)}
