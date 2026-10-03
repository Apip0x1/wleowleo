from sympy import factorint, isprime
from math import gcd, prod
from collections import Counter
from Crypto.Util.number import long_to_bytes, inverse
import random

def pollard_rho(n, max_iter=100000):
    if n % 2 == 0: return 2
    for _ in range(30):
        x = random.randrange(2, n)
        y = x
        c = random.randrange(1, n)
        d = 1
        for _ in range(max_iter):
            x = (x*x + c) % n
            y = (y*y + c) % n
            y = (y*y + c) % n
            d = gcd(abs(x-y), n)
            if d != 1: break
        if d != n and d != 1: return d
    return None

def factor_all(n):
    # PRIORITAS 1: sympy.factorint (paling canggih, ada ECM internal)
    try:
        fac = factorint(n)
        if fac and prod(p**k for p, k in fac.items()) == n:
            factors = []
            for p, k in fac.items():
                factors += [p] * k
            return sorted(factors)
    except Exception:
        pass
    
    # FALLBACK: trial + Pollard Rho
    factors = []
    stack = [n]
    while stack:
        x = stack.pop()
        if x == 1: continue
        if isprime(x):
            factors.append(x); continue
        found = False
        for p in range(2, 100000):
            if x % p == 0:
                factors.append(p); stack.append(x // p)
                found = True; break
        if found: continue
        d = pollard_rho(x)
        if d and d != x:
            stack.append(d); stack.append(x // d)
        else:
            factors.append(x)
    return sorted(factors)

def solve(n=None, e=None, c=None, data=None, **kwargs):
    if isinstance(n, dict): data = n
    if data:
        n = data.get('n'); e = data.get('e'); c = data.get('c')
    if not all([n, e, c]):
        return {"flag": None, "method": "multi_prime", "detail": "missing params"}

    # Guard: skip if n is too big for multi-prime factoring (only works for small factors)
    if n.bit_length() > 512:
        return {"flag": None, "method": "multi_prime", "detail": "n too large for multi_prime"}

    factors = factor_all(n)
    if len(factors) < 2 or prod(factors) != n:
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
