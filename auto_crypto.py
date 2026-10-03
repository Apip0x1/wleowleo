#!/usr/bin/env python3
import argparse
import sys
import os

from core.parser import parse_file
from core.dispatcher import dispatch

def main():
    parser = argparse.ArgumentParser(description="CTF Crypto Analyzer - ANTIGRAVITY IPB EDITION")
    parser.add_argument('-f', '--file', required=True, help="Path to challenge file")
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)
        
    print(f"[*] Analyzing: {args.file}")
    
    # 1. Parse File
    parsed_data = parse_file(args.file)
    print(f"[*] Extracted parameters: {list(parsed_data.keys())}")
    
    # 2. Dispatch to solvers
    print("[*] Dispatching to intelligence engine...")
    result = dispatch(parsed_data)
    
    # 3. Print Result
    if result.get('flag'):
        flag_str = result['flag']
        if isinstance(flag_str, bytes):
            try:
                flag_str = flag_str.decode('utf-8', 'ignore')
            except:
                flag_str = str(flag_str)
        print("\n" + "="*50)
        print(f"[!] FLAG FOUND: {flag_str.encode('ascii', 'ignore').decode()}")
        print(f"[*] Method: {result.get('method')}")
        print(f"[*] Detail: {result.get('detail')}")
        print("="*50 + "\n")
    else:
        print("\n[-] Analysis finished. No flag found.")
        print(f"[-] Detail: {result.get('detail')}\n")

if __name__ == "__main__":
    main()
