import os
import re
import subprocess
import tempfile
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

SAGE_BIN = "/home/apip/miniforge3/envs/sage_env/bin/sage"
if not os.path.exists(SAGE_BIN):
    import shutil
    SAGE_BIN = shutil.which("sage") or "sage"

def solve(n=None, e=None, c=None, prefix=None, filepath=None, data=None, **kwargs):
    if isinstance(n, dict):
        data = n
    if data:
        n = data.get('n'); e = data.get('e'); c = data.get('c')
        prefix = data.get('prefix'); filepath = data.get('filepath')

    # Look for ciphertext and plaintext in directory if filepath given
    directory = os.path.dirname(filepath) if filepath else '.'
    if not prefix and os.path.exists(os.path.join(directory, 'plaintext.txt')):
        try:
            pt = open(os.path.join(directory, 'plaintext.txt'), 'r', errors='ignore').read().strip()
            prefix = pt.rstrip('X')
        except:
            pass

    if not c and os.path.exists(os.path.join(directory, 'ciphertext')):
        try:
            raw = open(os.path.join(directory, 'ciphertext'), 'rb').read()
            try:
                c = int(raw.decode().strip(), 16)
            except:
                c = int.from_bytes(raw, 'big')
        except:
            pass

    if not n or not e or not c or not prefix:
        return {"flag": None, "method": "coppersmith_stereotyped", "detail": "Missing parameters"}

    if isinstance(prefix, str):
        prefix_bytes = prefix.encode()
    else:
        prefix_bytes = prefix

    unknown_bytes = 15
    if os.path.exists(os.path.join(directory, 'plaintext.txt')):
        full_pt = open(os.path.join(directory, 'plaintext.txt'), 'r', errors='ignore').read().strip()
        unknown_bytes = len(full_pt) - len(prefix)

    unknown_bits = max(8, unknown_bytes * 8)

    sage_code = f"""
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
    m = int(m_known * shift + int(r))
    msg = long_to_bytes(m)
    print("FLAG:" + msg.hex())
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sage', delete=False, dir='/tmp') as f:
        f.write(sage_code)
        path = f.name

    try:
        r = subprocess.run([SAGE_BIN, path], capture_output=True, text=True, timeout=45)
        m = re.search(r'FLAG:([0-9a-f]+)', r.stdout)
        if m:
            flag_bytes = bytes.fromhex(m.group(1))
            return {"flag": flag_bytes, "method": "coppersmith_stereotyped", "detail": "Solved via Sage small_roots"}
    except Exception as ex:
        return {"flag": None, "method": "coppersmith_stereotyped", "detail": str(ex)}
    finally:
        if os.path.exists(path):
            os.unlink(path)

    return {"flag": None, "method": "coppersmith_stereotyped", "detail": "No root found"}
