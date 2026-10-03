#!/usr/bin/env sage
from sage.all import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

base = "Crypton/RSA-encryption/Attack-Coppersmith/Challenges/stereotypes"

# --- Load pubkey ---
with open(f"{base}/pubkey.txt") as f:
    key = RSA.import_key(f.read())
N = key.n
e = key.e
print(f"[*] N = {N.bit_length()} bits")
print(f"[*] e = {e}")

# --- Load ciphertext ---
with open(f"{base}/ciphertext", "rb") as f:
    raw = f.read()
try:
    c = int(raw.decode().strip(), 16)
    print("[*] Ciphertext: hex")
except (ValueError, UnicodeDecodeError):
    c = int.from_bytes(raw, 'big')
    print("[*] Ciphertext: raw bytes")
print(f"[*] c = {c.bit_length()} bits")

# --- Load known prefix ---
with open(f"{base}/plaintext.txt") as f:
    pt = f.read().strip()
prefix = pt.rstrip("X")
print(f"[*] Prefix: {prefix[:60]}...")
print(f"[*] Prefix len: {len(prefix)} bytes")

# --- Unknown is 15 bytes ---
unknown_bits = 15 * 8   # 120 bits
X_bound = 2^unknown_bits
print(f"[*] Unknown bound: 2^{unknown_bits}")

# --- Build polynomial ---
m_known = bytes_to_long(prefix.encode())
shift = 2^unknown_bits
P.<x> = PolynomialRing(Zmod(N))
f = (m_known * shift + x)^e - c

# --- Coppersmith ---
print("[*] Running Coppersmith small_roots...")
roots = f.small_roots(X=X_bound, beta=1)
print(f"[*] Found {len(roots)} root(s)")

for r in roots:
    r = int(r)
    m = m_known * shift + r
    msg = long_to_bytes(m)
    print(f"[+] Flag candidate: {msg}")
