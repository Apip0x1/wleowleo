import time
import math
from Crypto.Util.number import getPrime, bytes_to_long, inverse
import threading
import sys

# Add current path
sys.path.append('.')

from attacks.rsa import fermat, wiener, pollard_pm1, common_modulus
from attacks.rsa import hint_linear, hint_d_squared

def run_with_timeout(func, args, timeout=10):
    result = [None]
    err = [None]
    def worker():
        try:
            result[0] = func(*args)
        except Exception as e:
            err[0] = e
    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return "TIMEOUT", None
    if err[0]:
        return "ERROR", err[0]
    return "OK", result[0]

def test_fermat():
    p = getPrime(512)
    q = p + 2
    while not math.gcd(q, 2) == 1: # just simple check, but q needs to be prime actually
        q += 2
    from sympy import isprime
    while not isprime(q):
        q += 2
    n = p * q
    e = 65537
    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    m = bytes_to_long(b"flag{test_fermat}")
    c = pow(m, e, n)
    
    status, res = run_with_timeout(fermat.solve, (n, e, c))
    print(f"fermat: {status}, {res}")

def test_wiener():
    while True:
        p = getPrime(512); q = getPrime(512)
        n = p * q
        phi = (p-1)*(q-1)
        d = getPrime(200)
        if math.gcd(d, phi) == 1:
            break
    e = inverse(d, phi)
    m = bytes_to_long(b"flag{test_wiener}")
    c = pow(m, e, n)
    
    status, res = run_with_timeout(wiener.solve, (n, e, c))
    print(f"wiener: {status}, {res}")

def test_hint_d_squared():
    p = getPrime(256); q = getPrime(256)
    n = p * q
    e = 65537
    phi = (p-1)*(q-1)
    d = inverse(e, phi)
    hint = d*d*p + e*e*q
    m = bytes_to_long(b"hacktoday{test_ipb_2025}")
    c = pow(m, e, n)
    
    status, res = run_with_timeout(hint_d_squared.solve, (n, e, hint, c), timeout=30)
    print(f"hint_d_squared: {status}, {res}")

if __name__ == "__main__":
    test_fermat()
    test_wiener()
    test_hint_d_squared()
