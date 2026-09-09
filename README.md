# dzk

Security utility toolkit for CTF and forensic analysis.


## Usage

dzk analyze suspicious.jpg  
dzk hash file.bin --algo sha256  
dzk metadata image.png  
dzk entropy encrypted.dat  
dzk strings binary.exe --min-len 6

## Features
File analysis (type, size, entropy)  
Hash calculation (MD5, SHA1, SHA256, SHA512)  
Metadata extraction  
Suspicious string detection  
Embedded file detection

## Usage
```bash
dzk analyze suspicious.jpg
dzk hash file.bin --algo sha256
dzk metadata image.png
dzk entropy encrypted.dat
dzk strings binary.exe --min-len 6
dzk dns example.com --type A
dzk http https://github.com
dzk pcap capture.pcap
```
## Example Output
```bash
dzk analyze suspicious.jpg

==================================================
[+] FILE ANALYSIS: suspicious.jpg
==================================================
[TYPE]    JPEG
[SIZE]    1.8 MB (1,843,200 bytes)
[ENTROPY] 6.8

[HASHES]
  MD5    : a1b2c3d4...
  SHA256 : e5f6g7h8...

[EMBEDDED]
  - ZIP
  - None detected

[SUSPICIOUS STRINGS]
  - admin_password
  - secret_key
==================================================
```
## Install

```bash
git clone https://github.com/daemon-dzk/dzk.git
cd dzk
pip install -e .

