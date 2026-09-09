#!/usr/bin/env python3
"""
dzk - Personal Security Utility Toolkit
"""

import sys
import argparse
from modules.analyze import analyze_file
from modules.hash import hash_file
from modules.metadata import get_metadata
from modules.entropy import calculate_entropy
from modules.strings import extract_strings
from modules.dns import query_dns
from modules.http import http_analyze
from modules.pcap import pcap_analyze


def main():
    parser = argparse.ArgumentParser(
        prog="dzk",
        description="Security utility toolkit for CTF and forensic analysis",
        epilog="Example: dzk analyze suspicious.jpg"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Module to run")
    
    # Module: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Full file analysis")
    analyze_parser.add_argument("target", help="File to analyze")
    analyze_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    # Module: hash
    hash_parser = subparsers.add_parser("hash", help="Calculate file hashes")
    hash_parser.add_argument("target", help="File to hash")
    hash_parser.add_argument("--algo", default="sha256", choices=["md5", "sha1", "sha256", "sha512"])
    
    # Module: metadata
    metadata_parser = subparsers.add_parser("metadata", help="Extract file metadata")
    metadata_parser.add_argument("target", help="File to analyze")
    
    # Module: entropy
    entropy_parser = subparsers.add_parser("entropy", help="Calculate file entropy")
    entropy_parser.add_argument("target", help="File to analyze")
    
    # Module: strings
    strings_parser = subparsers.add_parser("strings", help="Extract strings from file")
    strings_parser.add_argument("target", help="File to analyze")
    strings_parser.add_argument("--min-len", type=int, default=4, help="Minimum string length")
    
    # NEW: Module: dns
    dns_parser = subparsers.add_parser("dns", help="Query DNS records")
    dns_parser.add_argument("domain", help="Domain to query")
    dns_parser.add_argument("--type", "-t", default="A", choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME"], help="Record type")
    
    # NEW: Module: http
    http_parser = subparsers.add_parser("http", help="Analyze HTTP endpoint")
    http_parser.add_argument("url", help="URL to analyze")
    
    # NEW: Module: pcap
    pcap_parser = subparsers.add_parser("pcap", help="Analyze PCAP file")
    pcap_parser.add_argument("file", help="PCAP file to analyze")
    
    args = parser.parse_args()
    
    if args.command == "analyze":
        analyze_file(args.target, json_output=args.json)
    elif args.command == "hash":
        hash_file(args.target, args.algo)
    elif args.command == "metadata":
        get_metadata(args.target)
    elif args.command == "entropy":
        calculate_entropy(args.target)
    elif args.command == "strings":
        extract_strings(args.target, args.min_len)
    elif args.command == "dns":
        query_dns(args.domain, args.type)
    elif args.command == "http":
        http_analyze(args.url)
    elif args.command == "pcap":
        pcap_analyze(args.file)


if __name__ == "__main__":
    main()