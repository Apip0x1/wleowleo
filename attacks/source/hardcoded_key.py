import re
def solve(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        # Find keys that look like: key = b"secret", secret='...', flag = "picoCTF{...}"
        keys = re.findall(b'(?:key|secret|flag|iv)\s*=\s*b?[\'"]([^\'"]+)[\'"]', data, re.IGNORECASE)
        if keys:
            return {"flag": keys[0], "method": "hardcoded_key", "detail": f"Found {len(keys)} potential keys"}
        return {"flag": None, "method": "hardcoded_key", "detail": "No hardcoded key found"}
    except Exception as ex:
        return {"flag": None, "method": "hardcoded_key", "detail": str(ex)}
