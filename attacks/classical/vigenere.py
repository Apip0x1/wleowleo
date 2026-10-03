import re
import string
from collections import Counter
from math import gcd
from functools import reduce

def index_of_coincidence(text):
    text = [c for c in text.upper() if c.isalpha()]
    n = len(text)
    if n < 2: return 0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))

def find_repeated_seqs(text, min_len=3):
    seqs = {}
    for i in range(len(text) - min_len + 1):
        seq = text[i:i+min_len]
        if seq not in seqs:
            seqs[seq] = []
        seqs[seq].append(i)
    return {k: v for k, v in seqs.items() if len(v) > 1}

def get_kasiski_key_lengths(text, max_len=20):
    seqs = find_repeated_seqs(text, 3)
    distances = []
    for pos in seqs.values():
        for i in range(1, len(pos)):
            distances.append(pos[i] - pos[i-1])
    
    if not distances: return list(range(2, max_len+1))
    
    factors = Counter()
    for d in distances:
        for i in range(2, min(d+1, max_len+1)):
            if d % i == 0:
                factors[i] += 1
                
    return [k for k, v in factors.most_common(5)]

def solve(ct_text):
    try:
        if isinstance(ct_text, bytes): ct_text = ct_text.decode('utf-8', 'ignore')
        pure_text = ''.join(c for c in ct_text.upper() if c.isalpha())
        if not pure_text: return {"flag": None, "method": "vigenere", "detail": "No letters"}
        
        # English letter frequencies
        eng_freq = [0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,
                    0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,0.02360,0.00150,0.01974,0.00074]
        
        best_pt = ""
        best_score = -float('inf')
        
        key_lengths = get_kasiski_key_lengths(pure_text) or list(range(2, 15))
        
        for klen in key_lengths:
            key = []
            for i in range(klen):
                col = pure_text[i::klen]
                best_shift = 0
                max_dot = 0
                for shift in range(26):
                    shifted_col = [chr((ord(c) - ord('A') - shift) % 26 + ord('A')) for c in col]
                    counts = Counter(shifted_col)
                    dot = sum((counts.get(chr(ord('A')+j), 0)/len(col)) * eng_freq[j] for j in range(26))
                    if dot > max_dot:
                        max_dot = dot
                        best_shift = shift
                key.append(best_shift)
            
            # decrypt
            pt = []
            k_idx = 0
            for c in ct_text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    pt.append(chr((ord(c) - base - key[k_idx]) % 26 + base))
                    k_idx = (k_idx + 1) % klen
                else:
                    pt.append(c)
            
            pt_str = "".join(pt)
            if "{" in pt_str and "}" in pt_str:
                m = re.search(r'[A-Za-z0-9_]+{.*?}', pt_str)
                if m:
                    return {"flag": m.group(0).encode(), "method": "vigenere", "detail": f"KeyLen={klen}"}
                    
        return {"flag": None, "method": "vigenere", "detail": "Failed to find flag format"}
    except Exception as ex:
        return {"flag": None, "method": "vigenere", "detail": str(ex)}
