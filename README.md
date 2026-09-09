# dzk

> Personal security utility toolkit — one command, many capabilities.

`dzk` is a modular CLI toolkit built for CTF, forensic analysis, and security research. Instead of switching between `file`, `exiftool`, `binwalk`, `strings`, `dig`, `curl`, and `tshark`, you just use `dzk`.

## Usage

dzk <module> <target> [options]  
exam:  
dzk analyze suspicious.jpg  
dzk hash file.bin --algo sha256  
dzk metadata image.png  
dzk dns example.com --type A
dzk http https://github.com
dzk pcap capture.pcap
```
## Example Output

## Detailed Examples
### 1. File Analysis (analyze)

```bash
dzk analyze suspicious.jpg
$ dzk analyze sample.jpg

==================================================
[+] FILE ANALYSIS: suspicious.jpg
[+] FILE ANALYSIS: sample.jpg
==================================================
[TYPE]    JPEG
[SIZE]    1.8 MB (1,843,200 bytes)
[ENTROPY] 6.8

[HASHES]
  MD5    : a1b2c3d4...
  SHA256 : e5f6g7h8...
  MD5    : a1b2c3d4e5f6...
  SHA256 : 7g8h9i0j1k2l...

[EMBEDDED]
  - ZIP
  - None detected
  - ZIP (hidden archive detected)

[SUSPICIOUS STRINGS]
  - admin_password
  - secret_key
  - secret_key_123
==================================================
```
### 2. DNS Recon (dns)
```bash
$ dzk dns google.com --type A

[+] DNS QUERY: google.com (Type: A)
==================================================
[STATUS]  Success - 2 record(s) found
[ANSWERS]
  - 142.250.184.78
  - 142.250.184.78

[+] ADDITIONAL INFO
==================================================
[MX RECORDS]
  - alt4.aspmx.l.google.com (Priority: 50)
[NS RECORDS]
  - ns1.google.com
[TXT RECORDS]
  - google-site-verification=...
==================================================
```
### 3. HTTP Analysis (http)
```bash
$ dzk http https://example.com

[+] HTTP ANALYSIS: https://example.com
==================================================
[STATUS]    200 - OK
[SIZE]      1,256 bytes
[TIME]      0.234s
[ENCODING]  UTF-8

[HEADERS]
  [!] Server: nginx/1.18.0
  [!] X-Frame-Options: DENY
  [ ] Content-Type: text/html

[SSL/TLS]
  Issuer: DigiCert Inc
  Expires: Jun 15 23:59:59 2025 GMT
  Cipher: TLS_AES_256_GCM_SHA384
==================================================
```
### 4. PCAP Analysis (pcap)
```bash
$ dzk pcap capture.pcap

[+] PCAP ANALYSIS: capture.pcap
==================================================
[STATS]
  Total packets: 4,521

[PROTOCOLS]
  - TCP: 3,210 packets (71.0%)
  - UDP: 1,200 packets (26.5%)
  - ICMP: 111 packets (2.5%)

[TOP TALKERS]
  Source:
    - 192.168.1.10: 2,100 packets
    - 10.0.0.5: 890 packets
  Destination:
    - 8.8.8.8: 1,500 packets

[!] SUSPICIOUS FINDINGS
  - Metasploit port 4444 - 192.168.1.10:4444 -> 10.0.0.5:8080
  - Possible flag in packet: 192.168.1.10 -> 8.8.8.8
==================================================
```
## Dependencies
python-magic — File type detection  
dnspython — DNS queries  
requests — HTTP analysis  
scapy — PCAP analysis  
pyyaml — Configuration  
Install all with:
```bash
pip install -r requirements.txt
```

##  Quick Install

```bash
git clone https://github.com/daemon-dzk/dzk.git
cd dzk
pip install -r requirements.txt
pip install -e .
```
You can easily install `dzk` directly from PyPI using pip:

```bash
pip install dzk
```

### License
MIT — Use it, break it, fix it, share it.

