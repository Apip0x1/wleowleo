import re

with open("parser_chunk_0.txt", "r", encoding="utf-8") as f:
    c0 = f.read()

with open("parser_chunk_1.txt", "r", encoding="utf-8") as f:
    c1 = f.read()

# Extract lines from c0
lines_c0 = []
for line in c0.splitlines():
    m = re.match(r"^(\d+): (.*)$", line)
    if m:
        lines_c0.append((int(m.group(1)), m.group(2)))

# Extract lines from c1
lines_c1 = []
for line in c1.splitlines():
    m = re.match(r"^(\d+): (.*)$", line)
    if m:
        lines_c1.append((int(m.group(1)), m.group(2)))

all_lines = lines_c0 + lines_c1
all_lines.sort(key=lambda x: x[0])

# Deduplicate
seen = set()
clean_lines = []
for num, l in all_lines:
    if num not in seen:
        seen.add(num)
        clean_lines.append(l)

print(f"Total reconstructed lines: {len(clean_lines)}")
with open("reconstructed_parser.py", "w", encoding="utf-8") as out:
    out.write("\n".join(clean_lines) + "\n")

print("Wrote reconstructed_parser.py successfully!")
