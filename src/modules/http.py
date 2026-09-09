"""
HTTP analyzer - grab headers, certs, and security info
"""

import requests
import ssl
import socket
from urllib.parse import urlparse


def http_analyze(url: str):
    """Analyze HTTP/HTTPS endpoint"""
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    print(f"\n[+] HTTP ANALYSIS: {url}")
    print("=" * 50)
    
    try:
        # GET request with timeout
        response = requests.get(
            url, 
            timeout=10, 
            verify=True,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0 dzk-scanner/1.0'}
        )
        
        print(f"[STATUS]    {response.status_code} - {response.reason}")
        print(f"[SIZE]      {len(response.content):,} bytes")
        print(f"[TIME]      {response.elapsed.total_seconds():.3f}s")
        print(f"[ENCODING]  {response.encoding}")
        
        # Headers
        print(f"\n[HEADERS]")
        for key, value in response.headers.items():
            if key.lower() in ['server', 'x-powered-by', 'x-frame-options', 'content-security-policy']:
                print(f"  [!] {key}: {value}")  # Security-relevant headers
            else:
                print(f"  [ ] {key}: {value}")
        
        # Cookies
        if response.cookies:
            print(f"\n[COOKIES]")
            for cookie in response.cookies:
                print(f"  - {cookie.name}: {cookie.value[:30]}...")
        
        # SSL Certificate (if HTTPS)
        if url.startswith('https://'):
            print(f"\n[SSL/TLS]")
            hostname = urlparse(url).hostname
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    print(f"  Issuer: {cert.get('issuer', [''])[0]}")
                    print(f"  Subject: {cert.get('subject', [''])[0]}")
                    print(f"  Expires: {cert.get('notAfter', 'N/A')}")
                    print(f"  Version: {ssock.version()}")
                    print(f"  Cipher: {ssock.cipher()[0]}")
        
    except requests.exceptions.SSLError:
        print("[!] SSL Certificate error - try HTTP or ignore verification")
    except requests.exceptions.ConnectionError:
        print("[!] Connection failed - host unreachable")
    except requests.exceptions.Timeout:
        print("[!] Request timed out")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    print("=" * 50 + "\n")