# Python Port Scanner

A simple TCP port scanner written in Python. Supports multithreading, timeout control, and CSV export. Built for quick triage in lab or home networks.

## Features
- Scan a single host, hostname, or CIDR block
- Multithreaded for faster results
- Custom timeout and thread count
- CSV export of open port results

## Usage
```bash
python3 scanner.py -H 192.168.1.10 -p 20-1024 -t 200 --timeout 0.6 --csv results.csv
