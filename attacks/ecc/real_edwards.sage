import sys
import json
from mpmath import mp
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from sage.all import *

mp.dps = 200

if len(sys.argv) > 1:
    with open(sys.argv[1]) as f:
        content = f.read()
else:
    content = sys.stdin.read()

import re
j_match = re.search(r'\{[^{}]*"gx"[^{}]*\}', content, re.DOTALL)
if not j_match:
    sys.exit(1)

data = json.loads(j_match.group(0))

gx = mp.mpf(data['gx'])
gy = mp.mpf(data['gy'])
px = mp.mpf(data['px'])
py = mp.mpf(data['py'])
ciphertext = bytes.fromhex(data['ciphertext'])
iv = bytes.fromhex(data['iv'])

K = mp.ellipk(mp.mpf(0.5)) / mp.sqrt(2)
Omega = 4 * K

def point_to_theta(x, y):
    t = mp.asin(mp.sqrt(2) * abs(x))
    val = mp.ellipf(t, mp.mpf(0.5)) / mp.sqrt(2)
    if x >= 0 and y >= 1:
        return val
    elif x >= 0 and y <= -1:
        return 2*K - val
    elif x <= 0 and y <= -1:
        return 2*K + val
    else:
        return 4*K - val

theta_G = point_to_theta(gx, gy)
theta_P = point_to_theta(px, py)

alpha = theta_G / Omega
beta = theta_P / Omega

prec = 300
scale = 2**prec
A = int(mp.floor(alpha * scale))
B = int(mp.floor(beta * scale))

for weight in [2**128, 2**64, 1, 2**200]:
    Lat = Matrix(ZZ, [
        [scale, 0, 0],
        [A, weight, 0],
        [B, 0, scale // 2**128]
    ])
    Red = Lat.LLL()
    for row in Red:
        if row[2] != 0:
            cand_N = int(abs(row[1]) // weight)
            for sgn in [1, -1]:
                N_try = cand_N * sgn
                if N_try > 0 and N_try.bit_length() <= 128:
                    key = long_to_bytes(N_try, 16)
                    try:
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        pt = unpad(cipher.decrypt(ciphertext), 16)
                        print(f"FLAG FOUND: {pt.decode(errors='ignore')}")
                        sys.exit(0)
                    except:
                        pass
