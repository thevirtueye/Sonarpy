#!/usr/bin/env python3
"""
Sonarpy v5.0 - Advanced Network Scanner with TCP/UDP support
"""

import argparse
import ipaddress
import re
import socket
import sys
import time

from sonarpy.libs.colors import Colors
from sonarpy.libs.network import NetworkDiscovery
from sonarpy.libs.report import ReportGenerator
from sonarpy.libs.scanner import PortScanner
from sonarpy.libs.services import ServiceIdentifier

BANNER = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║  {Colors.RED}███████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗{Colors.CYAN} ║
║  {Colors.RED}██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝{Colors.CYAN} ║
║  {Colors.RED}███████╗██║   ██║██╔██╗ ██║███████║██████╔╝██████╔╝ ╚████╔╝ {Colors.CYAN} ║
║  {Colors.RED}╚════██║██║   ██║██║╚██╗██║██╔══██║██╔══██╗██╔═══╝   ╚██╔╝  {Colors.CYAN} ║
║  {Colors.RED}███████║╚██████╔╝██║ ╚████║██║  ██║██║  ██║██║        ██║   {Colors.CYAN} ║
║  {Colors.RED}╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝   {Colors.CYAN} ║
║                                                               ║
║  {Colors.WHITE}       TCP & UDP Scanner  |  github.com/thevirtueye{Colors.CYAN}          ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""


def parse_ports(port_string: str) -> list:
    ports = set()

    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                    ports.update(range(start, end + 1))
                else:
                    raise ValueError(f"Invalid port range: {part}")
            except ValueError:
                raise ValueError(f"Invalid range format: {part}")
        else:
            try:
                port = int(part)
                if 0 <= port <= 65535:
                    ports.add(port)
                else:
                    raise ValueError(f"Port out of range: {port}")
            except ValueError:
                raise ValueError(f"Invalid port: {part}")

    ports.discard(0)
    return sorted(list(ports))


def resolve_target(target: str) -> str:
    ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/([0-9]|[12][0-9]|3[0-2]))?$"

    if re.match(ip_regex, target):
        return target

    try:
        ip = socket.gethostbyname(target)
        print(f"{Colors.DIM}[*] Resolved {target} -> {ip}{Colors.RESET}")
        return ip
    except socket.gaierror:
        return ""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Sonarpy - Advanced Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sonarpy 192.168.1.1 -p 22,80,443
  sonarpy 192.168.1.0/24 -p 1-1000 --udp
  sonarpy scanme.nmap.org --top-ports 100
  sonarpy 10.0.0.1 -p 1-65535 --tcp --udp --format json
  sonarpy 192.168.1.1 -p 1-1000 --tcp --udp
  sonarpy 192.168.1.1 --top-ports 20 --format txt,json,csv
  sonarpy 192.168.1.50 -Pn --top-ports 50 --socket-mode
        """,
    )

    parser.add_argument(
        "target",
        help="Target IP, subnet or hostname (e.g. 192.168.1.1, 192.168.1.0/24, scanme.nmap.org)",
    )

    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument(
        "-p",
        "--ports",
        help="Ports to scan (e.g. 22 | 1-1000 | 22,80,443)",
    )
    port_group.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help="Scan top N most common ports (e.g. 20, 50, 100)",
    )

    parser.add_argument("--tcp", action="store_true", default=False, help="TCP scan")
    parser.add_argument("--udp", action="store_true", default=False, help="UDP scan")
    parser.add_argument(
        "--threads", type=int, default=100, help="Number of threads (default: 100)"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="scan_report",
        help="Report filename without extension (default: scan_report)",
    )
    parser.add_argument(
        "--format",
        type=str,
        default="txt",
        dest="output_format",
        help="Output format: txt, json, csv or comma-separated (default: txt)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--no-banner", action="store_true", help="Disable banner grabbing"
    )
    parser.add_argument(
        "--socket-mode",
        action="store_true",
        help="Use sockets only, no scapy (recommended on Windows)",
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Show only confirmed open ports (hides open|filtered)",
    )
    parser.add_argument(
        "--exclude-ports",
        type=str,
        default=None,
        help="Ports to exclude (e.g. 22,80 or 100-200)",
    )
    parser.add_argument(
        "-Pn",
        "--skip-discovery",
        action="store_true",
        help="Skip host discovery, treat all hosts as online",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Minimal output (open ports only, no decorations)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Sonarpy v5.0",
    )

    args = parser.parse_args()

    if not args.tcp and not args.udp:
        args.tcp = True

    target = resolve_target(args.target)
    if not target:
        print(f"{Colors.RED}[!] Invalid target: {args.target}{Colors.RESET}")
        print(
            f"{Colors.YELLOW}    Format: 192.168.1.1, 192.168.1.0/24 or hostname{Colors.RESET}"
        )
        sys.exit(1)

    if args.top_ports:
        ports = ServiceIdentifier.get_top_ports(args.top_ports)
    else:
        try:
            ports = parse_ports(args.ports)
            if not ports:
                raise ValueError("No ports specified")
        except ValueError as e:
            print(f"{Colors.RED}[!] Port error: {e}{Colors.RESET}")
            sys.exit(1)

    if args.exclude_ports:
        try:
            excluded = set(parse_ports(args.exclude_ports))
            ports = [p for p in ports if p not in excluded]
            if not ports:
                print(f"{Colors.RED}[!] All ports were excluded{Colors.RESET}")
                sys.exit(1)
        except ValueError as e:
            print(f"{Colors.RED}[!] Exclude ports error: {e}{Colors.RESET}")
            sys.exit(1)

    if not args.quiet:
        print(f"{Colors.GREEN}[*] Target: {target}{Colors.RESET}")
        if args.target != target:
            print(f"{Colors.GREEN}[*] Hostname: {args.target}{Colors.RESET}")
        print(
            f"{Colors.GREEN}[*] Ports: {len(ports)} ({min(ports)}-{max(ports)}){Colors.RESET}"
        )
        print(
            f"{Colors.GREEN}[*] Protocols: "
            f"{'TCP ' if args.tcp else ''}{'UDP' if args.udp else ''}{Colors.RESET}"
        )
        print(f"{Colors.GREEN}[*] Threads: {args.threads}{Colors.RESET}")
        print()

    if args.skip_discovery:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        else:
            targets = [target]
        if not args.quiet:
            print(f"{Colors.YELLOW}[*] Skipping host discovery (-Pn){Colors.RESET}")
    else:
        discovery = NetworkDiscovery()
        targets = discovery.discover(target, verbose=args.verbose)

    if not targets:
        print(f"{Colors.RED}[!] No active hosts found{Colors.RESET}")
        sys.exit(1)

    if not args.quiet:
        print(f"{Colors.GREEN}[+] Active hosts: {len(targets)}{Colors.RESET}")
        print()

    scanner = PortScanner(
        threads=args.threads,
        timeout=args.timeout,
        grab_banner=not args.no_banner,
        socket_only=args.socket_mode,
    )

    scan_start = time.time()
    all_results = []
    total_tcp_open = 0
    total_udp_open = 0

    for ip in targets:
        host_info = scanner.get_host_info(ip)
        hostname = host_info["hostname"]

        if not args.quiet:
            print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")
            print(f"{Colors.CYAN}[*] Scanning: {ip}{Colors.RESET}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

        results = {
            "ip": ip,
            "hostname": hostname,
            "os": host_info["os"],
            "tcp": [],
            "udp": [],
        }

        if args.tcp:
            if not args.quiet:
                print(f"\n{Colors.YELLOW}[TCP Scan]{Colors.RESET}")
            tcp_results = scanner.scan_tcp(ip, ports, verbose=args.verbose)
            results["tcp"] = tcp_results
            total_tcp_open += len(tcp_results)

            if tcp_results:
                if args.quiet:
                    for r in tcp_results:
                        print(
                            f"{ip}:{r['port']}/tcp open "
                            f"{r.get('service', '')} "
                            f"{r.get('banner', '')}"
                        )
                else:
                    print(
                        f"  {Colors.DIM}{'Port':<10} {'State':<8} "
                        f"{'Service':<18} {'Banner':<28} {'OS'}{Colors.RESET}"
                    )
                    print(f"  {Colors.DIM}{'-' * 85}{Colors.RESET}")

                    for r in tcp_results:
                        banner = r.get("banner", "-")
                        if banner and len(banner) > 28:
                            banner = banner[:25] + "..."
                        if not banner:
                            banner = "-"
                        os_info = r.get("os", "-") or "-"

                        print(
                            f"  {Colors.GREEN}{r['port']}/tcp{'':<4} "
                            f"{'open':<8} "
                            f"{r.get('service', 'unknown'):<18} "
                            f"{banner:<28} "
                            f"{os_info}{Colors.RESET}"
                        )
            elif not args.quiet:
                print(f"  {Colors.RED}No open TCP ports{Colors.RESET}")

        if args.udp:
            if not args.quiet:
                print(f"\n{Colors.YELLOW}[UDP Scan]{Colors.RESET}")
            udp_results = scanner.scan_udp(
                ip, ports, verbose=args.verbose, open_only=args.open_only
            )
            results["udp"] = udp_results
            total_udp_open += len(udp_results)

            if udp_results:
                if args.quiet:
                    for r in udp_results:
                        print(
                            f"{ip}:{r['port']}/udp {r['state']} "
                            f"{r.get('service', '')}"
                        )
                else:
                    print(
                        f"  {Colors.DIM}{'Port':<10} {'State':<15} "
                        f"{'Service':<18} {'OS'}{Colors.RESET}"
                    )
                    print(f"  {Colors.DIM}{'-' * 60}{Colors.RESET}")

                    for r in udp_results:
                        os_info = r.get("os", "-") or "-"
                        state_color = (
                            Colors.GREEN if r["state"] == "open" else Colors.YELLOW
                        )
                        print(
                            f"  {state_color}{r['port']}/udp{'':<4} "
                            f"{r['state']:<15} "
                            f"{r.get('service', 'unknown'):<18} "
                            f"{os_info}{Colors.RESET}"
                        )
            elif not args.quiet:
                print(f"  {Colors.RED}No open UDP ports detected{Colors.RESET}")

        all_results.append(results)
        if not args.quiet:
            print()

    scan_duration = time.time() - scan_start

    scan_params = {
        "threads": args.threads,
        "timeout": args.timeout,
        "mode": "socket" if args.socket_mode else "scapy",
        "banner": not args.no_banner,
    }

    report = ReportGenerator(args.output)
    generated_files = report.generate(
        all_results,
        target,
        ports,
        args.tcp,
        args.udp,
        output_format=args.output_format,
        duration=scan_duration,
        scan_params=scan_params,
    )

    if not args.quiet:
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.CYAN}  SCAN COMPLETE{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"  {Colors.GREEN}Hosts scanned:    {len(targets)}{Colors.RESET}")
        print(
            f"  {Colors.GREEN}Open ports:       "
            f"{total_tcp_open} TCP, {total_udp_open} UDP{Colors.RESET}"
        )
        print(
            f"  {Colors.GREEN}Duration:         "
            f"{report._format_duration(scan_duration)}{Colors.RESET}"
        )
        for f in generated_files:
            print(f"  {Colors.GREEN}Report saved:     {f}{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")


if __name__ == "__main__":
    main()
