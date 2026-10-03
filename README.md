# pwn_auto — CTF Pwn Automation Toolkit

Auto-assist untuk binary exploitation. **Bukan auto-solver.**
Keputusan strategi tetap manual; tool mempercepat kerja mekanik.

## Fitur
- Checksec akurat (pwntools + fallback checksec CLI)
- Analisis objdump: call berbahaya, indirect call, syscall, stack write
- Offset finder presisi via cyclic + gdb (bukan tebakan)
- ROP builder: ret2win, ret2libc, ret2syscall, one_gadget, ret2csu
- Heap helper: safe-linking, tcache poison, unsorted bin leak, FSOP template
- Bypass helper: leak libc / PIE / canary, partial overwrite, brute fork-server
- Template exploit skeleton (ret2win, ret2libc, ret2syscall, fmtstr, heap)

## Pemakaian
```bash
# Recon saja
python cli.py ./chall

# Recon + offset finder
python cli.py ./chall --offset rip

# Recon + ret2libc chain (butuh libc)
python cli.py ./chall --libc ./libc.so.6 --strategy ret2libc

# Heap mode
python cli.py ./chall --heap --strategy heap

# Remote
python cli.py ./chall --libc ./libc.so.6 --remote 1.2.3.4 1337 --strategy ret2libc

# Format string
python cli.py ./chall --strategy fmtstr --offset rip

# JSON output
python cli.py ./chall --json > recon.json

# Generate exploit skeleton
python cli.py ./chall --template ret2libc --libc ./libc.so.6
```

## Test lokal
```bash
cat <<'EOF' > test.c
#include <stdio.h>
void win(){ system("/bin/sh"); }
int main(){ char buf[64]; gets(buf); return 0; }
EOF
gcc -fno-stack-protector -z execstack -no-pie -o chall test.c
python cli.py ./chall --offset rip
python cli.py ./chall --strategy ret2win
```

## Batasan yang diakui
Tool **tidak** bisa auto-solve heap tanpa state machine user, SROP otomatis,
seccomp bypass, kernel pwn, atau memahami logika challenge.

## Prinsip
1. Tidak ada AI/LLM/cloud call.
2. Tidak hardcode offset — selalu cyclic_find().
3. Deteksi glibc runtime (safe-linking hanya jika ≥ 2.32).
4. Gagal → print saran manual, tidak crash.
5. Support 32/64-bit, static/dynamic, PIE/non-PIE.
# wleowleo
