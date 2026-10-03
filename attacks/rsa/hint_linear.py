import math
from math import isqrt
from sympy import symbols, solve as sym_solve

def decrypt(n, e, ct, p, q, method, detail=""):
    phi = (p-1)*(q-1)
    try:
        d = pow(e, -1, phi)
        m = pow(ct, d, n)
        flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        return {"flag": flag, "method": method, "detail": detail}
    except Exception as ex:
        return {"flag": None, "method": method, "detail": f"Decrypt error: {ex}"}

def solve(n, e, hint, ct):
    try:
        # 1. Coba p + q
        disc = hint**2 - 4*n
        if disc >= 0:
            s = isqrt(disc)
            if s*s == disc:
                p = (hint + s) // 2
                q = (hint - s) // 2
                if p * q == n:
                    return decrypt(n, e, ct, p, q, "hint_linear (p+q)", f"p={p}")

        # 2. Coba p - q
        s_sq = hint**2 + 4*n
        s = isqrt(s_sq)
        if s*s == s_sq:
            p = (s + hint) // 2
            q = (s - hint) // 2
            if p * q == n:
                return decrypt(n, e, ct, p, q, "hint_linear (p-q)", f"p={p}")

        # 3. Coba d + p (Bruteforce k)
        # (hint - p)*e = k*(p-1)(n/p - 1) + 1
        # Implementasi numeric sederhana via sympy
        p_sym = symbols('p', integer=True, positive=True)
        for k in range(1, min(e, 10000)):
            # e*(hint - p) * p = k*(p-1)*(n-p) + p
            eq = e*(hint - p_sym)*p_sym - k*(p_sym - 1)*(n - p_sym) - p_sym
            roots = sym_solve(eq, p_sym)
            for r in roots:
                if r > 1 and n % r == 0:
                    p = int(r)
                    q = n // p
                    return decrypt(n, e, ct, p, q, "hint_linear (d+p)", f"k={k}")

        return {"flag": None, "method": "hint_linear", "detail": "No linear hint matched"}
    except Exception as ex:
        return {"flag": None, "method": "hint_linear", "detail": str(ex)}
