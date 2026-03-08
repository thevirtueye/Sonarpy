# Sonarpy

Advanced network scanner with TCP and UDP support, built in Python.

## Features

- **TCP SYN Scan** — Stealth scanning using SYN packets (requires root/admin)
- **TCP Connect Scan** — Socket-based fallback, no privileges needed
- **UDP Scan** — Detect open/filtered UDP ports
- **Banner Grabbing** — Identify service versions (HTTP, SSH, FTP, SMTP, etc.)
- **OS Detection** — Fingerprint operating systems via TTL analysis
- **Network Discovery** — Scan subnets for active hosts (ICMP + ARP)
- **Top Ports** — Scan the N most common ports with `--top-ports`
- **Hostname Resolution** — Use hostnames as targets
- **Multiple Report Formats** — TXT, JSON, CSV (or all at once)
- **Multithreading** — Configurable thread count for fast scanning
- **Progress Bar** — Real-time progress with ETA
- **Quiet Mode** — Minimal output for scripting and piping
- **Cross-platform** — Linux, macOS, Windows (with `--socket-mode`)

## Requirements

- Python 3.8+
- Scapy 2.5+ (optional — not needed with `--socket-mode`)
- Root/admin privileges (for SYN scans only)

## Installation

```bash
git clone https://github.com/thevirtueye/sonarpy.git
cd sonarpy
pip install -e .
```

After installation, the `sonarpy` command is available system-wide.

Alternatively, run without installing:
```bash
python -m sonarpy -t 192.168.1.1 -p 1-1000
```

## Usage

### Basic TCP scan
```bash
sonarpy -t 192.168.1.1 -p 22,80,443
sonarpy -t 192.168.1.1 -p 1-1000
sonarpy -t 192.168.1.0/24 -p 1-1000
```

### Scan top N ports
```bash
sonarpy -t 192.168.1.1 --top-ports 20
sonarpy -t 10.0.0.1 --top-ports 100 --tcp --udp
```

### Hostname as target
```bash
sonarpy -t scanme.nmap.org --top-ports 50
```

### UDP scan
```bash
sonarpy -t 192.168.1.1 -p 53,123,161 --udp
```

### TCP + UDP combined
```bash
sonarpy -t 192.168.1.1 -p 1-1000 --tcp --udp
```

### Socket mode (no scapy, recommended on Windows)
```bash
sonarpy -t 192.168.1.1 -p 1-1000 --socket-mode
```

### Multiple report formats
```bash
sonarpy -t 192.168.1.1 -p 1-1000 --format txt,json,csv
```

### Show filtered UDP ports
```bash
sonarpy -t 192.168.1.1 -p 1-100 --udp --show-filtered
```

### Exclude ports
```bash
sonarpy -t 192.168.1.1 -p 1-1000 --exclude-ports 80,443
```

### Quiet mode (for scripting)
```bash
sonarpy -t 192.168.1.1 -p 1-1000 -q
```

### Full example
```bash
sonarpy -t 10.0.0.1 --top-ports 100 --tcp --udp --threads 200 -o my_report --format txt,json -v
```

## CLI Options

| Option | Description |
|---|---|
| `-t, --target` | Target IP, subnet or hostname |
| `-p, --ports` | Ports to scan (e.g. `22`, `1-1000`, `22,80,443`) |
| `--top-ports N` | Scan top N most common ports |
| `--tcp` | TCP scan (default if no protocol specified) |
| `--udp` | UDP scan |
| `--threads` | Thread count (default: 100) |
| `-o, --output` | Report filename without extension (default: `scan_report`) |
| `--format` | Output format: `txt`, `json`, `csv` or comma-separated (default: `txt`) |
| `--timeout` | Timeout in seconds (default: 1.0) |
| `--no-banner` | Disable banner grabbing |
| `--socket-mode` | Use sockets only, no scapy (more stable on Windows) |
| `--show-filtered` | Include open\|filtered UDP ports in results |
| `--exclude-ports` | Ports to exclude from scan |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Minimal output (open ports only) |
| `--version` | Show version |

## Project Structure

```
sonarpy/
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── sonarpy/
    ├── __init__.py
    ├── __main__.py
    ├── main.py
    └── libs/
        ├── __init__.py
        ├── scanner.py
        ├── network.py
        ├── banner.py
        ├── services.py
        ├── report.py
        └── colors.py
```

## Output Examples

### Terminal output
```
[*] Target: 192.168.1.1
[*] Ports: 100 (1-100)
[*] Protocols: TCP UDP
[+] Active hosts: 1

============================================================
[*] Scanning: 192.168.1.1
============================================================

[TCP Scan]
  [██████████████████████████████] 100% (100/100) ETA: 0s
  Port       State    Service            Banner                       OS
  -------------------------------------------------------------------------
  22/tcp     open     ssh                SSH-2.0-OpenSSH_8.9          Linux/Unix
  80/tcp     open     http               nginx/1.18.0                 Linux/Unix

============================================================
  SCAN COMPLETE
============================================================
  Hosts scanned:    1
  Open ports:       2 TCP, 0 UDP
  Duration:         12.3s
  Report saved:     scan_report.txt
============================================================
```

### Quiet mode output
```
192.168.1.1:22/tcp open ssh SSH-2.0-OpenSSH_8.9
192.168.1.1:80/tcp open http nginx/1.18.0
```

## Interrupt

Press `Ctrl+C` at any time to safely stop the scan.

## Notes

- SYN scans require root/admin privileges
- UDP scanning is slower and less reliable than TCP
- On Windows, use `--socket-mode` to avoid scapy issues
- Use responsibly — only scan networks you are authorized to scan

## Author

Alberto Cirillo (thevirtueye) — 2025

## License

MIT License
