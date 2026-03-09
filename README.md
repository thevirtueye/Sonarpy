# sonarpy

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)
![License MIT](https://img.shields.io/badge/License-MIT-green)
![Platform Linux | macOS | Windows](https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20Windows-lightgrey)

Advanced network scanner with TCP and UDP support, built in Python.

## Features

- TCP SYN scan (with root/admin privileges via Scapy) and TCP Connect scan (automatic fallback without privileges)
- UDP scan with open, open|filtered and filtered state detection
- Banner grabbing to identify service versions (HTTP, SSH, FTP, SMTP, etc.)
- OS detection via TTL fingerprinting
- Network discovery for scanning entire subnets
- Top ports scanning with separate TCP and UDP priority lists
- Multiple report formats: TXT, JSON, CSV
- Automatic retry mechanism for reliable results against rate-limiting targets
- Service identification with 110+ built-in services and system database fallback
- Multithreading with configurable thread count
- Progress bar with ETA
- Cross-platform: Linux, macOS, Windows

## Requirements

- Python 3.8+
- Scapy 2.5+ (optional, for SYN scans)
- Npcap (Windows only, required for Scapy)

## Installation

### Linux / macOS

```
git clone https://github.com/thevirtueye/sonarpy.git
cd sonarpy
pip install -e .
```

### Windows

Install [Npcap](https://npcap.com/#download) first (required for Scapy support).

```
git clone https://github.com/thevirtueye/sonarpy.git
cd sonarpy
py -m pip install -e .
```

Scapy is installed automatically. On Windows, Npcap is additionally required for Scapy to work. Without Npcap on Windows, Sonarpy falls back to socket-based scanning.

### Running

After installation, the `sonarpy` command is available system-wide.

On Linux/macOS, use `sudo sonarpy` for SYN scans. On Windows, run the terminal as Administrator.

## Usage

### TCP scan (default protocol)

```
sonarpy 192.168.1.1 -p 22,80,443
sonarpy 192.168.1.1 -p 1-1000
sonarpy 192.168.1.1 -p 20-25,80,443,3000-3389
sonarpy 192.168.1.1 --top-ports 50
```

### UDP scan

```
sonarpy 192.168.1.1 -p 53,123,161 --udp
sonarpy 192.168.1.1 --top-ports 20 --udp
```

### TCP and UDP combined

```
sonarpy 192.168.1.1 --top-ports 50 --tcp --udp
sonarpy 192.168.1.1 -p 1-1000 --tcp --udp
```

When using `--top-ports` with both protocols, Sonarpy selects ports appropriate for each protocol from separate priority lists (TCP max: 100, UDP max: 30).

### Scan an entire subnet

```
sonarpy 192.168.1.0/24 --top-ports 20
```

Discovers active hosts via ICMP ping, then scans each one.

### Skip host discovery

For targets that block ICMP (e.g. Windows machines with firewall enabled):

```
sonarpy 192.168.1.100 -Pn --top-ports 50
sonarpy 192.168.1.100 -Pn -p 1-1000
```

### Report formats

```
sonarpy 192.168.1.1 --top-ports 50 --format json
sonarpy 192.168.1.1 --top-ports 50 --format txt,json,csv
sonarpy 192.168.1.1 --top-ports 50 --format json -o my_report
```

### Show only confirmed open ports (UDP)

By default, UDP scan shows all states including open|filtered. To show only confirmed open ports:

```
sonarpy 192.168.1.1 --top-ports 30 --udp --open-only
```

### Performance tuning

```
sonarpy 192.168.1.1 -p 1-1000 --threads 50 --timeout 2 --retries 3
```

- `--threads`: parallel connections (default: 100). Lower values are more reliable against rate-limiting targets.
- `--timeout`: seconds to wait per port (default: 1.0). Increase for slow networks.
- `--retries`: attempts per port before marking as closed (default: 2). Increase for unreliable connections.

### Disable banner grabbing

For faster scans when service version detection is not needed:

```
sonarpy 192.168.1.1 -p 1-65535 --no-banner --threads 200
```

### SYN scan (with elevated privileges)

Running with root/admin privileges enables Scapy-based SYN scanning, which is more precise and stealthy:

```
sudo sonarpy 192.168.1.1 --top-ports 50
```

On Windows, run the terminal as Administrator instead of using sudo.

Without elevated privileges, Sonarpy automatically detects this and falls back to socket-based scanning with a notification message.

## CLI Reference

| Option | Description |
|---|---|
| `target` | Target IP or subnet (positional argument) |
| `-p, --ports` | Ports to scan (e.g. `22`, `1-1000`, `22,80,443`) |
| `--top-ports N` | Scan top N most common ports |
| `--tcp` | TCP scan (default if no protocol specified) |
| `--udp` | UDP scan |
| `--threads N` | Thread count (default: 100) |
| `-o, --output` | Report filename without extension (default: `scan_report`) |
| `--format FMT` | Output format: `txt`, `json`, `csv` or comma-separated (default: `txt`) |
| `--timeout N` | Timeout in seconds (default: 1.0) |
| `--retries N` | Retries per port (default: 2) |
| `--no-banner` | Disable banner grabbing |
| `--open-only` | Show only confirmed open ports |
| `-Pn` | Skip host discovery |
| `-h, --help` | Show help |

## Top Ports

Sonarpy includes a curated priority list for `--top-ports`:

- TCP: 100 ports covering web servers, databases, remote access, mail, and common services
- UDP: 30 ports covering DNS, DHCP, SNMP, NTP, VPN, and network services

The lists are defined in `sonarpy/libs/services.py` and can be customized. Service identification covers 110+ built-in entries with automatic fallback to the system services database for additional coverage.

## Project Structure

```
sonarpy/
├── pyproject.toml
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

## Notes

- SYN scans require root/admin privileges. Without them, Sonarpy falls back to connect scans automatically.
- UDP scanning is inherently slower and less reliable than TCP due to the nature of the protocol.
- The retry mechanism helps against targets that rate-limit connections. Increase `--retries` and decrease `--threads` for stubborn targets.
- On Windows, Npcap is required only for Scapy-based SYN scans. Without Npcap, Sonarpy works with socket-based scanning.
- Use responsibly. Only scan networks you are authorized to scan.


## License

This project is released under the **MIT License**.  
Free to use for educational and research purposes. Please credit the author where applicable.


## Author

Created by **Alberto Cirillo** — 2026
