import json
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional


class ReportGenerator:

    def __init__(self, filename: str = "scan_report"):
        self.filename = filename
        self.timestamp = datetime.now()

    def _format_duration(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"

    def generate_txt(
        self,
        results: List[Dict],
        target: str,
        ports: List[int],
        tcp: bool,
        udp: bool,
        duration: Optional[float] = None,
        scan_params: Optional[Dict] = None,
    ) -> str:
        filepath = f"{self.filename}.txt"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("                    SONARPY - SCAN REPORT\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Scan date:       {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target:          {target}\n")
            f.write(f"Ports:           {len(ports)} ({min(ports)}-{max(ports)})\n")
            f.write(f"Protocols:       {'TCP ' if tcp else ''}{'UDP' if udp else ''}\n")
            f.write(f"Hosts found:     {len(results)}\n")

            if duration is not None:
                f.write(f"Duration:        {self._format_duration(duration)}\n")

            if scan_params:
                f.write(f"Threads:         {scan_params.get('threads', 'N/A')}\n")
                f.write(f"Timeout:         {scan_params.get('timeout', 'N/A')}s\n")
                f.write(f"Mode:            {scan_params.get('mode', 'scapy')}\n")
                f.write(f"Banner grab:     {scan_params.get('banner', True)}\n")

            f.write("\n" + "-" * 70 + "\n\n")

            total_tcp_open = sum(len(r.get("tcp", [])) for r in results)
            total_udp_open = sum(len(r.get("udp", [])) for r in results)

            f.write("SUMMARY\n")
            f.write("-" * 30 + "\n")
            if tcp:
                f.write(f"Open TCP ports:       {total_tcp_open}\n")
            if udp:
                f.write(f"Open UDP ports:       {total_udp_open}\n")
            f.write(f"Total open ports:     {total_tcp_open + total_udp_open}\n")
            f.write("\n" + "-" * 70 + "\n\n")

            for host_result in results:
                ip = host_result.get("ip", "unknown")
                hostname = host_result.get("hostname", "unknown")

                f.write(f"HOST: {ip}\n")
                f.write("=" * 50 + "\n\n")

                tcp_ports = host_result.get("tcp", [])
                if tcp_ports:
                    f.write("  [TCP]\n")
                    f.write("  " + "-" * 95 + "\n")
                    f.write(
                        f"  {'IP':<16} {'Hostname':<20} {'Port':<8} "
                        f"{'State':<8} {'Banner':<25} {'OS'}\n"
                    )
                    f.write("  " + "-" * 95 + "\n")

                    for port_info in tcp_ports:
                        port = port_info.get("port", "")
                        state = port_info.get("state", "")
                        banner = port_info.get("banner", "-")
                        os_info = port_info.get("os", "-")
                        hostname_display = hostname if hostname != "unknown" else "-"

                        if banner and len(banner) > 25:
                            banner = banner[:22] + "..."
                        if not banner:
                            banner = "-"
                        if not os_info:
                            os_info = "-"

                        f.write(
                            f"  {ip:<16} {hostname_display:<20} {port:<8} "
                            f"{state:<8} {banner:<25} {os_info}\n"
                        )

                    f.write("\n")

                udp_ports = host_result.get("udp", [])
                if udp_ports:
                    f.write("  [UDP]\n")
                    f.write("  " + "-" * 75 + "\n")
                    f.write(
                        f"  {'IP':<16} {'Hostname':<20} {'Port':<8} "
                        f"{'State':<15} {'OS'}\n"
                    )
                    f.write("  " + "-" * 75 + "\n")

                    for port_info in udp_ports:
                        port = port_info.get("port", "")
                        state = port_info.get("state", "")
                        os_info = port_info.get("os", "-")
                        hostname_display = hostname if hostname != "unknown" else "-"

                        if not os_info:
                            os_info = "-"

                        f.write(
                            f"  {ip:<16} {hostname_display:<20} {port:<8} "
                            f"{state:<15} {os_info}\n"
                        )

                    f.write("\n")

                if not tcp_ports and not udp_ports:
                    f.write("  No open ports detected.\n\n")

                f.write("\n")

            f.write("-" * 70 + "\n")
            f.write(f"Report generated by Sonarpy v5.0\n")
            f.write(f"Timestamp: {self.timestamp.isoformat()}\n")
            f.write("=" * 70 + "\n")

        return filepath

    def generate_json(
        self,
        results: List[Dict],
        target: str,
        ports: List[int],
        tcp: bool,
        udp: bool,
        duration: Optional[float] = None,
        scan_params: Optional[Dict] = None,
    ) -> str:
        filepath = f"{self.filename}.json"

        total_tcp = sum(len(r.get("tcp", [])) for r in results)
        total_udp = sum(len(r.get("udp", [])) for r in results)

        report = {
            "metadata": {
                "tool": "Sonarpy",
                "version": "5.0",
                "scan_date": self.timestamp.isoformat(),
                "target": target,
                "port_range": f"{min(ports)}-{max(ports)}",
                "port_count": len(ports),
                "protocols": {
                    "tcp": tcp,
                    "udp": udp,
                },
            },
            "summary": {
                "hosts_scanned": len(results),
                "tcp_open": total_tcp,
                "udp_open": total_udp,
                "total_open": total_tcp + total_udp,
            },
            "hosts": results,
        }

        if duration is not None:
            report["metadata"]["duration_seconds"] = round(duration, 2)

        if scan_params:
            report["metadata"]["parameters"] = scan_params

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return filepath

    def generate_csv(
        self,
        results: List[Dict],
        target: str,
        ports: List[int],
        tcp: bool,
        udp: bool,
    ) -> str:
        filepath = f"{self.filename}.csv"

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["IP", "Hostname", "Port", "Protocol", "State", "Service", "Banner", "OS"]
            )

            for host in results:
                ip = host.get("ip", "")
                hostname = host.get("hostname", "")

                for port_info in host.get("tcp", []):
                    writer.writerow([
                        ip,
                        hostname,
                        port_info.get("port", ""),
                        "tcp",
                        port_info.get("state", ""),
                        port_info.get("service", ""),
                        port_info.get("banner", ""),
                        port_info.get("os", ""),
                    ])

                for port_info in host.get("udp", []):
                    writer.writerow([
                        ip,
                        hostname,
                        port_info.get("port", ""),
                        "udp",
                        port_info.get("state", ""),
                        port_info.get("service", ""),
                        port_info.get("banner", ""),
                        port_info.get("os", ""),
                    ])

        return filepath

    def generate(
        self,
        results: List[Dict],
        target: str,
        ports: List[int],
        tcp: bool = True,
        udp: bool = False,
        output_format: str = "txt",
        duration: Optional[float] = None,
        scan_params: Optional[Dict] = None,
    ) -> List[str]:
        generated = []

        formats = [f.strip() for f in output_format.split(",")]

        for fmt in formats:
            if fmt == "txt":
                generated.append(
                    self.generate_txt(results, target, ports, tcp, udp, duration, scan_params)
                )
            elif fmt == "json":
                generated.append(
                    self.generate_json(results, target, ports, tcp, udp, duration, scan_params)
                )
            elif fmt == "csv":
                generated.append(
                    self.generate_csv(results, target, ports, tcp, udp)
                )

        return generated
