from collections import Counter
from math import prod, gcd
from Crypto.Util.number import long_to_bytes, inverse
import random

try:
    import gmpy2
    def is_prime(x): return gmpy2.is_prime(x)
    def my_gcd(a, b): return int(gmpy2.gcd(a, b))
except:
    from sympy import isprime as is_prime
    def my_gcd(a, b): return gcd(a, b)

import time

def pollard_rho_brent(n, max_r=70000, deadline=None):
    if n % 2 == 0: return 2
    for _ in range(3):
        if deadline and time.time() > deadline:
            break
        y = random.randint(1, n - 1)
        c = random.randint(1, n - 1)
        m = random.randint(1, min(100, n - 1))
        g, r, q = 1, 1, 1
        while g == 1 and r < max_r:
            if deadline and time.time() > deadline:
                return None
            x = y
            for _ in range(r):
                y = (pow(y, 2, n) + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (pow(y, 2, n) + c) % n
                    q = (q * abs(x - y)) % n
                g = my_gcd(q, n)
                k += m
            r *= 2
        if g == n:
            while True:
                ys = (pow(ys, 2, n) + c) % n
                g = my_gcd(abs(x - ys), n)
                if g > 1: break
        if 1 < g < n:
            return g
    return None

def factor_all(n, max_seconds=5):
    t0 = time.time()
    deadline = t0 + max_seconds
    factors = []
    stack = [n]
    while stack:
        if time.time() > deadline:
            return []
        x = stack.pop()
        if x == 1: continue
        if is_prime(x):
            factors.append(x)
            continue
        # trial small
        found = False
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            if x % p == 0:
                factors.append(p)
                stack.append(x // p)
                found = True
                break
        if found: continue

        f = pollard_rho_brent(x, deadline=deadline)
        if f and 1 < f < x:
            stack.append(f)
            stack.append(x // f)
        else:
            factors.append(x)
    return sorted(factors)

def solve(n=None, e=None, c=None, data=None, **kwargs):
    if isinstance(n, dict): data = n
    if data:
        n = data.get('n'); e = data.get('e'); c = data.get('c')
    if not all([n, e, c]):
        return {"flag": None, "method": "multi_prime", "detail": "missing params"}

    factors = factor_all(n)
    if len(factors) < 3 or prod(factors) != n or any(not is_prime(f) for f in factors):
        return {"flag": None, "method": "multi_prime", "detail": f"got {len(factors)} factors, verify fail"}

    cnt = Counter(factors)
    phi = 1
    for p, k in cnt.items():
        phi *= (p - 1) * p ** (k - 1)

    if gcd(e, phi) != 1:
        return {"flag": None, "method": "multi_prime", "detail": f"gcd(e,phi)={gcd(e,phi)}"}

    d = inverse(e, phi)
    m = pow(c, d, n)
    return {"flag": long_to_bytes(m), "method": "multi_prime", "detail": f"{len(factors)} factors"}

if __name__ == "__main__":
    pass
