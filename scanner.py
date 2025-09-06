#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def parse_args():
    p = argparse.ArgumentParser(description="Simple TCP port scanner")
    p.add_argument("-H", "--hosts", required=True,
                   help="Target host, CIDR, or host range. Examples: 192.168.1.10 or 192.168.1.0/24")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="Ports or range. Examples: 22,80,443 or 1-1024")
    p.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    p.add_argument("--timeout", type=float, default=0.8, help="Socket timeout in seconds")
    p.add_argument("--csv", default=None, help="CSV output filename")
    return p.parse_args()

def expand_hosts(host_expr):
    # Accept single IP, hostname, or CIDR
    try:
        # CIDR
        net = ipaddress.ip_network(host_expr, strict=False)
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    except ValueError:
        # Not a CIDR. Could be hostname or single IP
        return [host_expr]

def expand_ports(port_expr):
    ports = set()
    for part in str(port_expr).split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def scan_one(host, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return (host, port, result == 0)
    except Exception:
        return (host, port, False)

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

def main():
    args = parse_args()
    targets = expand_hosts(args.hosts)
    ports = expand_ports(args.ports)
    timeout = args.timeout
    threads = max(1, args.threads)

    # Resolve hostnames to IPs but keep original for display
    resolved = {h: resolve_host(h) for h in targets}
    work = []
    for h in targets:
        ip = resolved[h]
        for p in ports:
            work.append((ip, p, h))  # store original host text as well

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting scan")
    print(f"Targets: {', '.join(targets)}")
    print(f"Ports: {args.ports}")
    print(f"Threads: {threads}  Timeout: {timeout}s\n")

    open_results = []
    total = len(work)
    done = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_one, ip, port, timeout): (orig, ip, port) for (ip, port, orig) in work}
        for fut in as_completed(futures):
            orig, ip, port = futures[fut]
            ok = False
            try:
                _, _, ok = fut.result()
            except Exception:
                ok = False

            if ok:
                print(f"[+] {orig} ({ip}):{port} open")
                open_results.append((orig, ip, port))

            done += 1
            if done % 500 == 0 or done == total:
                pct = (done / total) * 100
                print(f"... progress {done}/{total} ({pct:.1f}%)")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host_input", "ip", "port", "status"])
            for orig, ip, port in open_results:
                w.writerow([orig, ip, port, "open"])
        print(f"\nSaved CSV to {args.csv}")

    print("\nScan complete.")
    if open_results:
        print("Open ports found:")
        for orig, ip, port in open_results:
            print(f" - {orig} ({ip}):{port}")
    else:
        print("No open ports discovered.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
