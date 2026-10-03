"""Generate test .txt files dari pola CryptoHack RSA challenges."""
from Crypto.Util.number import getPrime, bytes_to_long, inverse
from math import gcd
import os

os.makedirs('cryptohack_tests', exist_ok=True)
FLAG = b"crypto{auto_crypto_test}"

def save(name, content):
    path = f"cryptohack_tests/{name}.txt"
    open(path, 'w').write(content)
    print(f"[+] {path}")

# 1. BASIC RSA (Factoring) — p, q kecil
p = getPrime(128); q = getPrime(128)
n = p * q; e = 65537
phi = (p-1)*(q-1)
d = inverse(e, phi)
c = pow(bytes_to_long(FLAG), e, n)
save("01_basic_rsa", f"n = {n}\ne = {e}\nc = {c}")

# 2. MULTI-PRIME (Manyprime) — 4 faktor
primes = [getPrime(64) for _ in range(4)]
n = 1
for pp in primes: n *= pp
e = 65537
phi = 1
for pp in primes: phi *= (pp-1)
d = inverse(e, phi)
c = pow(bytes_to_long(FLAG), e, n)
save("02_multi_prime", f"n = {n}\ne = {e}\nc = {c}")

# 3. FERMAT (Infinite Descent) — p, q dekat
p = getPrime(256)
q = p + 2
while not __import__('sympy').isprime(q): q += 2
n = p * q; e = 65537
phi = (p-1)*(q-1)
d = inverse(e, phi)
c = pow(bytes_to_long(FLAG), e, n)
save("03_fermat", f"n = {n}\ne = {e}\nc = {c}")

# 4. WIENER — d kecil
while True:
    p = getPrime(512); q = getPrime(512)
    n = p * q
    phi = (p-1)*(q-1)
    d = getPrime(200)  # d < n^0.25
    if gcd(d, phi) == 1 and d < n ** 0.25:
        break
e = inverse(d, phi)
c = pow(bytes_to_long(FLAG), e, n)
save("04_wiener", f"n = {n}\ne = {e}\nc = {c}")

# 5. COMMON MODULUS (Crossed Wires)
p = getPrime(512); q = getPrime(512)
n = p * q
phi = (p-1)*(q-1)
e1, e2 = 65537, 17
while gcd(e1, phi) != 1: e1 = getPrime(17)
while gcd(e2, phi) != 1 or gcd(e1, e2) != 1: e2 = getPrime(17)
m = bytes_to_long(FLAG)
c1 = pow(m, e1, n)
c2 = pow(m, e2, n)
save("05_common_modulus", f"n = {n}\ne1 = {e1}\nc1 = {c1}\ne2 = {e2}\nc2 = {c2}")

# 6. SMALL E (Salty) — e=3, m^3 < n
p = getPrime(1024); q = getPrime(1024)
n = p * q
e = 3
m = bytes_to_long(FLAG)
c = pow(m, e, n)
save("06_small_e", f"n = {n}\ne = {e}\nc = {c}")

# 7. SHARED PRIME (Ron was Wrong) — 2 N share faktor
p = getPrime(512)
q1 = getPrime(512); q2 = getPrime(512)
n1 = p * q1
n2 = p * q2
e = 65537
c1 = pow(bytes_to_long(FLAG), e, n1)
save("07_shared_prime", f"n1 = {n1}\nn2 = {n2}\ne = {e}\nc1 = {c1}")

# 8. HASTAD (Endless Emails) — e=3, 3 penerima
m = bytes_to_long(FLAG)
moduli = []
ct = []
for _ in range(3):
    p = getPrime(512); q = getPrime(512)
    nn = p * q
    moduli.append(nn)
    ct.append(pow(m, 3, nn))
save("08_hastad", 
    f"n1 = {moduli[0]}\nc1 = {ct[0]}\n"
    f"n2 = {moduli[1]}\nc2 = {ct[1]}\n"
    f"n3 = {moduli[2]}\nc3 = {ct[2]}\ne = 3")

print("\n[+] Semua file dibuat di cryptohack_tests/")
