import re

def extract_strings(filepath, min_len=4):
    with open(filepath, 'rb') as f:
        data = f.read()
    strings = re.findall(rb'[ -~]{%d,}' % min_len, data)
    for s in strings[:20]:
        print(s.decode('ascii', errors='ignore'))