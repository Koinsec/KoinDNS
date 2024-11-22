#!/usr/bin/env python3

import socket
import argparse
from termcolor import colored

def resolve_dns(domain):
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        return ip_addresses
    except socket.gaierror:
        print(colored(f"[!] Failed to resolve domain: {domain}", "red"))
        return []

def check_spoof(domain, resolved_ips, trusted_ips=None):

    print(colored(f"\n[+] Resolved IPs for {domain}: {', '.join(resolved_ips)}", "blue"))
    if trusted_ips:
        print(colored(f"[+] Trusted IPs: {', '.join(trusted_ips)}", "blue"))
        for ip in resolved_ips:
            if ip not in trusted_ips:
                print(colored(f"[!] WARNING: {ip} is not a trusted IP!", "yellow"))
        if set(resolved_ips) == set(trusted_ips):
            print(colored("[+] All resolved IPs match the trusted IPs.", "green"))
        else:
            print(colored("[!] DNS spoofing detected: Some IPs don't match!", "red"))
    elif len(resolved_ips) > 1:
        print(colored("[!] Multiple IPs detected, which could indicate DNS spoofing!", "yellow"))
    else:
        print(colored("[+] Single IP detected, likely no spoofing.", "green"))

def main():
    parser = argparse.ArgumentParser(
        description="DNS Spoof Detector: Detect anomalies in DNS resolutions."
    )
    parser.add_argument(
        "-d", "--domain", required=True, help="The domain to resolve (e.g., example.com)"
    )
    parser.add_argument(
        "-t",
        "--trusted-ips",
        nargs="+",
        help="List of trusted IPs to compare against (e.g., -t 93.184.216.34 1.1.1.1)",
    )

    args = parser.parse_args()
    domain = args.domain
    trusted_ips = args.trusted_ips

    print(colored("[*] Starting DNS spoof detection...", "cyan"))
    resolved_ips = resolve_dns(domain)
    if resolved_ips:
        check_spoof(domain, resolved_ips, trusted_ips)
    else:
        print(colored("[!] No IPs resolved. Exiting.", "red"))

if __name__ == "__main__":
    main()
