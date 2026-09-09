"""
DNS query module - dig alternative with more detail
"""

import dns.resolver
import dns.exception


def query_dns(domain: str, record_type: str = "A"):
    """Query DNS records for a domain"""
    
    print(f"\n[+] DNS QUERY: {domain} (Type: {record_type})")
    print("=" * 50)
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        answers = resolver.resolve(domain, record_type)
        
        print(f"[STATUS]  Success - {len(answers)} record(s) found")
        print(f"[ANSWERS]")
        for rdata in answers:
            print(f"  - {rdata.to_text()}")
            
    except dns.resolver.NXDOMAIN:
        print("[!] Domain does not exist")
    except dns.resolver.NoAnswer:
        print(f"[!] No {record_type} record found for this domain")
    except dns.resolver.NoNameservers:
        print("[!] No nameservers responded")
    except Exception as e:
        print(f"[!] Error: {e}")

    # Bonus: Get common records if A is requested
    if record_type == "A":
        print(f"\n[+] ADDITIONAL INFO")
        print("=" * 50)
        
        # MX
        try:
            mx = resolver.resolve(domain, "MX")
            print("[MX RECORDS]")
            for r in mx:
                print(f"  - {r.exchange} (Priority: {r.preference})")
        except:
            pass
        
        # NS
        try:
            ns = resolver.resolve(domain, "NS")
            print("[NS RECORDS]")
            for r in ns:
                print(f"  - {r.target}")
        except:
            pass
        
        # TXT
        try:
            txt = resolver.resolve(domain, "TXT")
            print("[TXT RECORDS]")
            for r in txt:
                for s in r.strings:
                    text = s.decode('utf-8', errors='ignore')
                    if len(text) > 100:
                        text = text[:100] + "..."
                    print(f"  - {text}")
        except:
            pass
    
    print("=" * 50 + "\n")