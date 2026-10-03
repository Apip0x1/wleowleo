import re
def solve(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
        m = re.search(r'random\.seed\(\s*(\d+)\s*\)', src)
        if m:
            seed = int(m.group(1))
            return {"flag": None, "method": "weak_seed", "detail": f"Found random.seed({seed})"}
        return {"flag": None, "method": "weak_seed", "detail": "No weak seed found"}
    except Exception as e:
        return {"flag": None, "method": "weak_seed", "detail": str(e)}
