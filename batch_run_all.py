import subprocess
import os
import sys
import time

crypton_files = [
    "Crypton/Elgamal-Encryption/Challenges/Prime-Enigma/ciphertext.txt",
    "Crypton/RSA-encryption/Attack-Common-Modulus/Challenges/RSA-1s-Fun/ciphertext.txt",
    "Crypton/RSA-encryption/Attack-Common-Modulus/Challenges/RSA-1s-Fun/modulus.txt",
    "Crypton/RSA-encryption/Attack-Coppersmith/Challenges/Really-Suspicious-Acronym/output.txt",
    "Crypton/RSA-encryption/Attack-Coppersmith/Challenges/stereotypes/plaintext.txt",
    "Crypton/RSA-encryption/Attack-Coppersmith/Challenges/stereotypes/pubkey.txt",
    "Crypton/RSA-encryption/Attack-Hastad-Broadcast/Challenges/Multicast/data.txt",
    "Crypton/RSA-encryption/Attack-Wiener-variant/Challenges/Gracias/enc_pubkey.txt",
    "Crypton/RSA-encryption/Attack-Wiener/Challenges/Multi_Layer_RSA/ciphertext.txt",
    "Crypton/RSA-encryption/Attack-Wiener/Challenges/Multi_Layer_RSA/modulus.txt",
    "Crypton/RSA-encryption/Factorisation-Fermat/Challenges/Crafted-RSA/ciphertext.txt",
    "Crypton/RSA-encryption/Factorisation-Fermat/Challenges/Crafted-RSA/modulus.txt",
    # "Crypton/RSA-encryption/Factorisation-Pollard's_p-1/Challenges/handicraft_rsa/output.txt",  # SKIPPED
    "Crypton/RSA-encryption/Intro-Challenges/7h3_Godf4ther/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/C4-reloaded/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Challenge-0/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Challenge-1/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Challenge-1/privatekey.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Challenge-2/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Challenge-3/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Challenge-4/ciphertext.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Dp&Dq/data.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Labyrinth-of-Suffering/data.txt",
    "Crypton/RSA-encryption/Intro-Challenges/Meth_M4th/data.txt",
]

archive_files = [
    "CTF-Archive/PatriotCTF/2025/cry/MatrixReconstruction/cipher.txt",
    "CTF-Archive/PatriotCTF/2025/cry/NonceTwice,PaythePrice/sig1.txt",
    "CTF-Archive/GlacierCTF/2025/crypto/032_Noisy Neighbour/files/noisy_neighbour/output.txt",
    "CTF-Archive/NCWBinusCTF/2025/Cryptography/014_salvage/files/output.txt",
    "CTF-Archive/NCWBinusCTF/2025/Cryptography/015_wassup twin/files/output.txt",
    "CTF-Archive/NCWBinusCTF/2025/Cryptography/016_echoed symphony/files/output.txt",
]

solo_files = [
    "challenges_solo/message.txt",
    "challenges_solo/output.txt",
    "challenges_solo/pico.txt",
]

google_files = [
    "google-ctf/2020/quals/crypto-chunk-norris/output.txt",
]

all_targets = [
    ("Crypton", crypton_files),
    ("CTF-Archive", archive_files),
    ("challenges_solo", solo_files),
    ("google-ctf", google_files),
]

python_bin = "/home/apip/miniforge3/bin/python"

total_solved = 0
total_tested = 0
results = []

for group_name, files in all_targets:
    print(f"\n==================================================")
    print(f"[*] RUNNING BATCH: {group_name} ({len(files)} files)")
    print(f"==================================================")
    for idx, fpath in enumerate(files, 1):
        if not os.path.exists(fpath):
            print(f"[{idx}/{len(files)}] {fpath} -> MISSING FILE")
            results.append((fpath, "MISSING", "-", "-"))
            continue
        
        t0 = time.time()
        try:
            p = subprocess.run(
                [python_bin, "auto_crypto.py", "-f", fpath],
                capture_output=True,
                text=True,
                timeout=30
            )
            dur = time.time() - t0
            out = p.stdout
            if "[!] FLAG FOUND:" in out:
                # Extract flag and method
                flag = "-"
                method = "-"
                for line in out.splitlines():
                    if "[!] FLAG FOUND:" in line:
                        flag = line.split("[!] FLAG FOUND:")[1].strip()
                    elif "[*] Method:" in line:
                        method = line.split("[*] Method:")[1].strip()
                print(f"[{idx}/{len(files)}] {fpath} -> SOLVED [{method}] in {dur:.2f}s : {flag}")
                results.append((fpath, "SOLVED", method, flag))
                total_solved += 1
            else:
                print(f"[{idx}/{len(files)}] {fpath} -> UNRESOLVED in {dur:.2f}s")
                results.append((fpath, "UNRESOLVED", "-", "-"))
        except subprocess.TimeoutExpired:
            print(f"[{idx}/{len(files)}] {fpath} -> TIMEOUT (>30s)")
            results.append((fpath, "TIMEOUT", "-", "-"))
        except Exception as e:
            print(f"[{idx}/{len(files)}] {fpath} -> ERROR: {e}")
            results.append((fpath, "ERROR", str(e), "-"))
        total_tested += 1

print("\n" + "="*60)
print(f"FINAL SUMMARY: {total_solved}/{total_tested} SOLVED")
print("="*60)

with open("BATCH_RUN_REPORT.md", "w") as out:
    out.write(f"# BATCH RUN REPORT\n\nTotal Tested: {total_tested}\nTotal Solved: {total_solved}\n\n")
    out.write("| File | Status | Method | Flag |\n|---|---|---|---|\n")
    for fp, stat, meth, flg in results:
        out.write(f"| `{fp}` | **{stat}** | {meth} | `{flg}` |\n")
