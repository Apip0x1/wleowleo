"""Wrapper untuk panggil Sage dari Python biasa."""
import subprocess, tempfile, os, re


def run_sage(code, timeout=60):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sage', delete=False, dir='.') as f:
        f.write(code)
        path = f.name
    try:
        r = subprocess.run(['sage', path], capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    finally:
        os.unlink(path)


def solve_coppersmith_stereotyped(n, e, c, prefix_bytes, unknown_bits=120):
    code = f"""
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

N = {n}
e = {e}
c = {c}
prefix = {prefix_bytes!r}
unknown_bits = {unknown_bits}

m_known = bytes_to_long(prefix)
shift = 2^unknown_bits
X_bound = 2^unknown_bits

P.<x> = PolynomialRing(Zmod(N))
f = (m_known * shift + x)^e - c
roots = f.small_roots(X=X_bound, beta=1)

for r in roots:
    m = int(m_known * shift + r)
    print("FLAG:" + long_to_bytes(m).hex())
"""
    out, err = run_sage(code, timeout=60)
    m = re.search(r'FLAG:([0-9a-f]+)', out)
    if m:
        return bytes.fromhex(m.group(1))
    return None
