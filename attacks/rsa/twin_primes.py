import math
import re
from Crypto.Util.number import long_to_bytes, inverse, isPrime

def solve(n=None, e=None, c=None, raw_text=None, filepath=None, **kwargs):
    """
    Solves RSA where p and q are twin primes (q = p + 2) or very close.
    Also handles small moduli where m > n via prefix/suffix residue search.
    """
    if not n or not e or not c:
        return {"flag": None, "method": "twin_primes", "detail": "Missing n, e, or c"}

    p, q = None, None
    # Check exact twin primes: N = p(p+2) = (p+1)^2 - 1 => N + 1 = (p+1)^2
    s = math.isqrt(n + 1)
    if s * s == n + 1:
        p = s - 1
        q = s + 1
    else:
        # Check close primes with small difference k: N + k^2 = (p+k)^2
        for diff in range(4, 200, 2):
            k = diff // 2
            if n + k * k >= 0:
                s = math.isqrt(n + k * k)
                if s * s == n + k * k:
                    p = s - k
                    q = s + k
                    if p * q == n:
                        break
        else:
            return {"flag": None, "method": "twin_primes", "detail": "n is not a product of twin/close primes"}

    if not p or not q or p * q != n:
        return {"flag": None, "method": "twin_primes", "detail": "Factoring failed"}

    phi = (p - 1) * (q - 1)
    try:
        d = inverse(e, phi)
    except:
        return {"flag": None, "method": "twin_primes", "detail": "e not invertible mod phi"}

    m0 = pow(c, d, n)
    pt_bytes = long_to_bytes(m0)

    # 1. Direct check
    flag_match = re.search(rb'[A-Za-z0-9_]+\{[^}]+\}', pt_bytes)
    if flag_match:
        return {
            "flag": flag_match.group(0),
            "method": "twin_primes",
            "detail": f"Decrypted directly (twin primes p={p}, q={q})"
        }

    # 2. If n is small and flag is larger than n: m = k * n + m0
    # Search for flag with known prefixes and suffix '}'
    text_data = raw_text or ""
    if filepath and not text_data:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                text_data = f.read()
        except:
            pass

    # Extract potential prefixes
    prefixes = set(["flag{", "ctf{", "picoCTF{", "crypto{"])
    found_prefixes = re.findall(r'([A-Za-z0-9_]+)\{', text_data)
    for pfx in found_prefixes:
        prefixes.add(pfx + "{")

    # Extract potential length hints (e.g. "# 23 <- hint" or len=23)
    hint_lengths = set()
    for m in re.finditer(r'(\d+)\s*(?:<-|#|hint|len)', text_data, re.IGNORECASE):
        try:
            val = int(m.group(1))
            if 16 <= val <= 64:
                hint_lengths.add(val)
        except:
            pass
            
    # Default range of lengths to test if no explicit hint
    if not hint_lengths:
        hint_lengths = range(16, 36)

    # Modular inverse of n mod 256 for fast search (suffix is '}')
    inv_n_256 = inverse(n % 256, 256) if (n % 2 == 1) else None

    for L in sorted(hint_lengths):
        for pref in prefixes:
            pref_bytes = pref.encode()
            if len(pref_bytes) >= L:
                continue
            p_int = int.from_bytes(pref_bytes, 'big')
            shift = 8 * (L - len(pref_bytes))
            min_m = p_int << shift
            max_m = (p_int + 1) << shift

            min_k = (min_m - m0) // n
            max_k = (max_m - m0) // n

            if min_k < 0:
                min_k = 0
            if max_k < min_k:
                continue

            num_candidates = max_k - min_k
            if inv_n_256 is not None:
                num_candidates //= 256

            if num_candidates > 2_000_000:
                continue

            target_rem = ((125 - m0) * inv_n_256) % 256 if inv_n_256 else 0
            step = 256 if inv_n_256 else 1
            start_k = min_k + (target_rem - min_k % 256) % 256 if inv_n_256 else min_k

            for cand_k in range(start_k, max_k + 1, step):
                cand_m = cand_k * n + m0
                cand_b = long_to_bytes(cand_m)
                if cand_b.startswith(pref_bytes) and cand_b.endswith(b"}"):
                    if all(32 <= b <= 126 for b in cand_b):
                        return {
                            "flag": cand_b,
                            "method": "twin_primes",
                            "detail": f"Decrypted m > n via twin primes (k={cand_k})"
                        }

    return {
        "flag": None,
        "method": "twin_primes",
        "detail": f"Factored n into twin primes (p={p}, q={q}) but could not reconstruct m"
    }
