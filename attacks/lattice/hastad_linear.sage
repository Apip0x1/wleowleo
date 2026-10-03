#!/usr/bin/env sage
from sage.all import *

data_path = "Crypton/RSA-encryption/Attack-Hastad-Broadcast/Challenges/Multicast/data.txt"
lines = [l.strip() for l in open(data_path).read().splitlines() if l.strip()]

a, b, c, n = [], [], [], []
for i in range(0, len(lines), 4):
    a.append(Integer(lines[i]))
    b.append(Integer(lines[i+1]))
    c.append(Integer(lines[i+2]))
    n.append(Integer(lines[i+3]))

e = 5
N = prod(n)
print(f"[*] N bits: {N.bit_length()}, recipients: {len(n)}")

T = []
for i in range(len(n)):
    ni = n[i]
    Ni = N // ni
    inv = inverse_mod(Ni, ni)
    T.append(Ni * inv)

P.<x> = PolynomialRing(Zmod(N))
g = sum(T[i] * ((a[i]*x + b[i])^e - c[i]) for i in range(len(n)))

print("[*] Making polynomial monic...")
g = g.monic()

print("[*] Running small_roots (Coppersmith)...")
roots = g.small_roots(X=2^512, beta=1)
print(f"[*] Found {len(roots)} root(s): {roots}")

for r in roots:
    hex_str = hex(int(r))[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    try:
        flag = bytes.fromhex(hex_str)
        print(f"[!] FLAG FOUND: {flag.decode()}")
    except Exception as ex:
        print(f"[-] Raw root bytes: {bytes.fromhex(hex_str)}")
