import re
def solve(ct_text):
    try:
        if isinstance(ct_text, bytes): ct_text = ct_text.decode('utf-8', 'ignore')
        
        for shift in range(26):
            pt = ""
            for c in ct_text:
                if 'a' <= c <= 'z':
                    pt += chr((ord(c) - ord('a') - shift) % 26 + ord('a'))
                elif 'A' <= c <= 'Z':
                    pt += chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                else:
                    pt += c
            if "{" in pt and "}" in pt:
                m = re.search(r'[A-Za-z0-9_]+{.*?}', pt)
                if m:
                    return {"flag": m.group(0).encode(), "method": "caesar", "detail": f"Shift {shift}"}
        return {"flag": None, "method": "caesar", "detail": "No flag format found"}
    except Exception as ex:
        return {"flag": None, "method": "caesar", "detail": str(ex)}
