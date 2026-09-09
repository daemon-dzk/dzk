"""
PCAP analyzer - packet dissection and suspicious detection
"""

import os
from collections import Counter

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw, ARP, DNS
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    exit(1)


def pcap_analyze(filepath: str):
    """Analyze PCAP file"""
    
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return
    
    print(f"\n[+] PCAP ANALYSIS: {filepath}")
    print("=" * 50)
    
    try:
        packets = rdpcap(filepath)
        total = len(packets)
        
        print(f"[STATS]")
        print(f"  Total packets: {total}")
        
        if total == 0:
            print("[!] Empty PCAP file")
            return
        
        # Protocol distribution
        proto_count = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        suspicious = []
        
        for pkt in packets:
            if IP in pkt:
                proto_count[pkt[IP].proto] += 1
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1
                
                # Detect suspicious
                if pkt[IP].dst == '255.255.255.255':
                    suspicious.append(f"Broadcast from {pkt[IP].src}")
                
                if TCP in pkt:
                    if pkt[TCP].dport == 4444 or pkt[TCP].sport == 4444:
                        suspicious.append(f"Metasploit port 4444 - {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
                    if pkt[TCP].flags & 0x02 and pkt[TCP].flags & 0x04:  # SYN+ACK
                        pass  # normal
                
                if Raw in pkt:
                    payload = pkt[Raw].load
                    if b'flag{' in payload or b'FLAG{' in payload:
                        suspicious.append(f"Possible flag in packet: {pkt[IP].src} -> {pkt[IP].dst}")
                    if b'pass' in payload.lower() or b'password' in payload.lower():
                        suspicious.append(f"Sensitive keyword 'password' in packet: {pkt[IP].src} -> {pkt[IP].dst}")
            
            if ARP in pkt:
                if pkt[ARP].op == 2:  # ARP Reply
                    suspicious.append(f"ARP Reply (possible spoof) - {pkt[ARP].psrc} is at {pkt[ARP].hwsrc}")
        
        # Protocol mapping
        proto_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        print(f"\n[PROTOCOLS]")
        for proto, count in proto_count.most_common():
            name = proto_names.get(proto, f'Unknown({proto})')
            print(f"  - {name}: {count} packets ({count/total*100:.1f}%)")
        
        # Top talkers
        print(f"\n[TOP TALKERS]")
        print("  Source:")
        for ip, count in src_ips.most_common(5):
            print(f"    - {ip}: {count} packets")
        print("  Destination:")
        for ip, count in dst_ips.most_common(5):
            print(f"    - {ip}: {count} packets")
        
        # Suspicious findings
        if suspicious:
            print(f"\n[!] SUSPICIOUS FINDINGS")
            for s in suspicious[:10]:
                print(f"  - {s}")
        
        # HTTP requests (bonus)
        print(f"\n[HTTP REQUESTS]")
        http_found = 0
        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if 'GET /' in payload or 'POST /' in payload or 'Host:' in payload:
                        lines = payload.split('\n')
                        for line in lines[:3]:
                            if 'GET' in line or 'POST' in line or 'Host:' in line:
                                print(f"  - {line.strip()[:80]}")
                                http_found += 1
                                break
                except:
                    pass
        
        if http_found == 0:
            print("  - No HTTP requests detected")
        
        print("=" * 50 + "\n")
        
    except Exception as e:
        print(f"[!] Error reading PCAP: {e}")