# Python Port Scanner

A simple TCP port scanner written in Python. Supports multithreading, timeout control, and CSV export. Built for quick triage in lab or home networks.

## Features
- Scan a single host, hostname, or CIDR block
- Multithreaded for faster results
- Custom timeout and thread count
- CSV export of open port results

## Usage
```bash
# Extract to CSV
python3 scanner.py -H 192.168.1.10 -p 20-1024 -t 200 --timeout 0.6 --csv results.csv

# Single host common range
python3 scanner.py -H 10.0.0.5 -p 1-1024

# Hostname
python3 scanner.py -H example.com -p 22,80,443

# CIDR
python3 scanner.py -H 192.168.1.0/24 -p 80,443 -t 300 --timeout 0.5
