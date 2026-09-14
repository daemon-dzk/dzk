"""
Full file analysis module - The Swiss Army knife
"""
import math
import os
import json
import hashlib
import struct
from typing import Dict, Any


MAGIC_SIGNATURES = {
    b'\xFF\xD8\xFF': 'JPEG',
    b'\x89PNG\r\n\x1a\n': 'PNG',
    b'%PDF': 'PDF',
    b'PK\x03\x04': 'ZIP',
    b'\x7fELF': 'ELF',
    b'MZ': 'PE (Windows)',
    b'GIF8': 'GIF',
    b'BM': 'BMP',
    b'RIFF': 'RIFF (AVI/WAV)',
}


def detect_file_type(filepath: str) -> str:
    """Detect file type using magic bytes"""
    with open(filepath, 'rb') as f:
        header = f.read(10)
    
    for magic, filetype in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            return filetype
    return 'Unknown'


def calculate_entropy_bytes(data: bytes) -> float:
    """Calculate Shannon entropy of bytes"""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return round(entropy, 4)


def analyze_file(filepath: str, json_output: bool = False):
    """Main analysis function"""
    
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return
    
    stats = os.stat(filepath)
    file_size = stats.st_size
    
    # Read file
    with open(filepath, 'rb') as f:
        data = f.read(8192)  # Read first 8KB for analysis
    
    # Hashes
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    
    # File type
    file_type = detect_file_type(filepath)
    
    # Entropy
    entropy_score = calculate_entropy_bytes(data)
    
    # Embedded files (simple detection)
    embedded = []
    for magic, name in MAGIC_SIGNATURES.items():
        if data.find(magic) != -1 and magic != data[:len(magic)]:
            embedded.append(name)
    
    # Suspicious strings
    strings_found = []
    import re
    for match in re.finditer(rb'[ -~]{8,}', data):
        string = match.group().decode('ascii', errors='ignore')
        if any(kw in string.lower() for kw in ['admin', 'pass', 'key', 'secret', 'flag']):
            strings_found.append(string)
    
    # Output
    result = {
        'file': {
            'name': os.path.basename(filepath),
            'type': file_type,
            'size': f"{file_size:,} bytes ({file_size / 1024:.2f} KB)"
        },
        'hash': {
            'md5': md5,
            'sha256': sha256
        },
        'entropy': entropy_score,
        'embedded': embedded if embedded else ['None detected'],
        'suspicious_strings': strings_found if strings_found else ['None found']
    }
    
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "="*50)
        print(f"[+] FILE ANALYSIS: {result['file']['name']}")
        print("="*50)
        print(f"[TYPE]    {result['file']['type']}")
        print(f"[SIZE]    {result['file']['size']}")
        print(f"[ENTROPY] {result['entropy']} {'(HIGH - possible encryption/compression)' if result['entropy'] > 7 else ''}")
        print(f"\n[HASHES]")
        print(f"  MD5    : {result['hash']['md5']}")
        print(f"  SHA256 : {result['hash']['sha256']}")
        print(f"\n[EMBEDDED]")
        for item in result['embedded']:
            print(f"  - {item}")
        print(f"\n[SUSPICIOUS STRINGS]")
        for s in result['suspicious_strings'][:5]:
            print(f"  - {s}")
        print("="*50 + "\n")