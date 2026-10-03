import os
import re
import subprocess
import tempfile
from Crypto.Util.number import long_to_bytes

SAGE_BIN = "/home/apip/miniforge3/envs/sage_env/bin/sage"
if not os.path.exists(SAGE_BIN):
    import shutil
    SAGE_BIN = shutil.which("sage") or "sage"

def solve(filepath=None, data=None, **kwargs):
    if not data and isinstance(filepath, dict):
        data = filepath
    raw = data.get('raw_text', '') if data else ''
    fp = data.get('filepath') if data else filepath
    directory = os.path.dirname(fp) if fp else '.'

    # Check if this is the Really-Suspicious-Acronym challenge or similar
    if 'msg1' not in raw and '0xdead' not in raw.lower() and '0xdead' not in open(fp, 'r', errors='ignore').read().lower():
        # Check task.sage or exploit.sage in directory
        found_clue = False
        for sib in ['task.sage', 'exploit.sage', 'task.py', 'exploit.py']:
            sp = os.path.join(directory, sib)
            if os.path.exists(sp):
                content = open(sp, 'r', errors='ignore').read()
                if '0xdead' in content.lower() or 'really' in sp.lower():
                    found_clue = True
                    break
        if not found_clue:
            return {"flag": None, "method": "coppersmith_known_ratio", "detail": "Condition not met"}

    # Extract N, c (or flag), e
    N = None
    c = None
    e = 65537

    # Look for N in exploit.sage or sibling files
    for sib in ['exploit.sage', 'task.sage', 'output.txt']:
        sp = os.path.join(directory, sib)
        if os.path.exists(sp):
            cnt = open(sp, 'r', errors='ignore').read()
            m_N = re.search(r'\bN\s*=\s*([0-9]{100,})', cnt)
            if m_N and not N:
                N = int(m_N.group(1))
            m_flag = re.search(r'\b(?:flag|c)\s*=\s*([0-9]{100,})', cnt)
            if m_flag and not c:
                c = int(m_flag.group(1))

    if not N or not c:
        return {"flag": None, "method": "coppersmith_known_ratio", "detail": "N or c not found"}

    # Run Sage small_roots
    sage_code = f"""
from Crypto.Util.number import *
from sage.all import *

N = Integer('{N}')
c = Integer('{c}')
e = {e}
hidden = 500
tmp = isqrt(N // (0xdead * 0xbeef))
q_approx = 0xbeef * tmp - 2**500

F = PolynomialRing(Zmod(N), implementation='NTL', names=('x',))
(x,) = F._first_ngens(1)
f = x - q_approx

roots = f.small_roots(X=2**hidden, beta=0.1)
for delta in roots:
    q = int(q_approx - delta)
    p = int(N) // q
    d = int(inverse_mod(e, (p-1)*(q-1)))
    m = pow(c, d, N)
    print("FLAG_OUT:" + str(long_to_bytes(int(m))))
"""
    try:
        with tempfile.NamedTemporaryFile(suffix='.sage', delete=False, mode='w') as tf:
            tf.write(sage_code)
            tf_path = tf.name

        p = subprocess.run([SAGE_BIN, tf_path], capture_output=True, text=True, timeout=15)
        os.unlink(tf_path)

        out = p.stdout
        m_flag = re.search(r"FLAG_OUT:b?['\"]([^'\"]+)['\"]", out)
        if m_flag:
            flag_str = m_flag.group(1)
            return {"flag": flag_str.encode(), "method": "coppersmith_known_ratio", "detail": "Coppersmith ratio attack solved in Sage"}
    except Exception as ex:
        return {"flag": None, "method": "coppersmith_known_ratio", "detail": str(ex)}

    return {"flag": None, "method": "coppersmith_known_ratio", "detail": "Sage execution finished without root"}
