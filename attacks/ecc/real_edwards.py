import os
import subprocess
import re

def solve(gx=None, gy=None, px=None, py=None, filepath=None, raw_text=None, **kwargs):
    """
    Solves ECDLP on an Edwards Curve over the real numbers R.
    Uses elliptic integrals (ellipk, ellipf) to map points to the circle group R/Omega,
    then uses CVP via LLL to recover the integer scalar key N.
    """
    if not (gx and gy and px and py):
        return {"flag": None, "method": "real_edwards", "detail": "Missing curve points gx, gy, px, py"}

    sage_path = "/home/apip/miniforge3/envs/sage_env/bin/sage"
    script_path = os.path.join(os.path.dirname(__file__), "real_edwards.sage")

    if not os.path.exists(sage_path):
        return {"flag": None, "method": "real_edwards", "detail": "SageMath environment not found"}

    try:
        input_file = filepath
        if not input_file or not os.path.exists(input_file):
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tf:
                tf.write(raw_text or "")
                input_file = tf.name

        proc = subprocess.run([sage_path, script_path, input_file], capture_output=True, text=True, timeout=30)
        out = proc.stdout
        for line in out.splitlines():
            if "FLAG FOUND:" in line:
                flag = line.split("FLAG FOUND:")[1].strip()
                return {
                    "flag": flag.encode(),
                    "method": "real_edwards",
                    "detail": "Recovered scalar N via elliptic integrals and LLL"
                }

        return {"flag": None, "method": "real_edwards", "detail": "Sage real_edwards script finished without finding flag"}
    except Exception as ex:
        return {"flag": None, "method": "real_edwards", "detail": str(ex)}
