from Crypto.Util.number import getPrime, bytes_to_long, inverse
from math import gcd
from attacks.rsa.common_modulus import solve

# Generate
p = getPrime(1024); q = getPrime(1024)
n = p*q
e1, e2 = 9, 123
assert gcd(e1, e2) == 3
m = bytes_to_long(b"test_flag{common_modulus}")
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)

# Test
r = solve(n=n, e1=e1, c1=c1, e2=e2, c2=c2)
assert r["flag"] == b"test_flag{common_modulus}", r
print("[PASS] Test A")
