import os
import re
import sys
import socket
import logging
import threading
import time
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from .banner import BannerGrabber
from .services import ServiceIdentifier
from .colors import Colors

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy").setLevel(logging.CRITICAL)

if os.name == "nt":
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)

_scapy_lock = threading.Lock() if os.name == "nt" else None


class PortScanner:

    def __init__(
        self,
        threads: int = 100,
        timeout: float = 1.0,
        grab_banner: bool = True,
        socket_only: bool = False,
    ):
        self.threads = threads
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.socket_only = socket_only
        self.banner_grabber = BannerGrabber(timeout=timeout)
        self.service_id = ServiceIdentifier()
        self._os_cache = {}

    def _detect_os(self, ttl: int) -> str:
        if 0 < ttl <= 64:
            return "Linux/Unix"
        elif 64 < ttl <= 128:
            return "Windows"
        elif 128 < ttl <= 255:
            return "Cisco/Network Device"
        else:
            return f"Unknown (TTL={ttl})"

    def _detect_os_ping(self, ip: str) -> str:
        if ip in self._os_cache:
            return self._os_cache[ip]

        try:
            import subprocess

            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            match = re.search(r"ttl[=:](\d+)", result.stdout, re.IGNORECASE)

            if match:
                ttl = int(match.group(1))
                os_detected = self._detect_os(ttl)
                self._os_cache[ip] = os_detected
                return os_detected

            self._os_cache[ip] = "Unknown"
            return "Unknown"
        except Exception:
            self._os_cache[ip] = "Unknown"
            return "Unknown"

    def _get_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "unknown"

    def get_host_info(self, ip: str) -> Dict:
        return {
            "hostname": self._get_hostname(ip),
            "os": self._detect_os_ping(ip),
        }

    def _scan_tcp_port_scapy(self, ip: str, port: int) -> Optional[Dict]:
        try:
            from scapy.all import IP, TCP, sr1, send, RandShort, conf

            conf.verb = 0

            syn_packet = IP(dst=ip) / TCP(
                sport=RandShort(), dport=port, flags="S"
            )

            if _scapy_lock:
                with _scapy_lock:
                    try:
                        response = sr1(syn_packet, timeout=self.timeout, verbose=0)
                    except OSError:
                        return self._scan_tcp_port_socket(ip, port)
            else:
                response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response is None:
                return None

            if TCP in response:
                flags = response[TCP].flags

                if flags == 0x12:
                    try:
                        rst_packet = IP(dst=ip) / TCP(
                            sport=syn_packet[TCP].sport, dport=port, flags="R"
                        )
                        if _scapy_lock:
                            with _scapy_lock:
                                send(rst_packet, verbose=0)
                        else:
                            send(rst_packet, verbose=0)
                    except Exception:
                        pass

                    result = {
                        "port": port,
                        "state": "open",
                        "protocol": "tcp",
                        "service": self.service_id.get_service(port, "tcp"),
                        "os": self._detect_os(response[IP].ttl),
                        "ttl": response[IP].ttl,
                    }

                    if self.grab_banner:
                        banner = self.banner_grabber.grab(ip, port)
                        if banner:
                            result["banner"] = banner

                    return result

                elif flags & 0x04:
                    return None

            return None

        except ImportError:
            return self._scan_tcp_port_socket(ip, port)
        except Exception:
            return self._scan_tcp_port_socket(ip, port)

    def _scan_tcp_port_socket(self, ip: str, port: int) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result_code = sock.connect_ex((ip, port))

            if result_code == 0:
                result = {
                    "port": port,
                    "state": "open",
                    "protocol": "tcp",
                    "service": self.service_id.get_service(port, "tcp"),
                    "os": self._detect_os_ping(ip),
                }

                if self.grab_banner:
                    banner = self.banner_grabber.grab(ip, port)
                    if banner:
                        result["banner"] = banner

                sock.close()
                return result

            sock.close()
            return None
        except Exception:
            return None

    def _scan_udp_port(self, ip: str, port: int) -> Optional[Dict]:
        if os.name == "nt":
            return self._scan_udp_port_socket(ip, port)

        try:
            from scapy.all import IP, UDP, ICMP, sr1, conf

            conf.verb = 0

            payloads = {
                53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                123: b"\x1b" + 47 * b"\x00",
                161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04",
                137: b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
            }

            payload = payloads.get(port, b"")
            udp_packet = IP(dst=ip) / UDP(dport=port) / payload
            response = sr1(udp_packet, timeout=self.timeout * 2, verbose=0)

            if response is None:
                return {
                    "port": port,
                    "state": "open|filtered",
                    "protocol": "udp",
                    "service": self.service_id.get_service(port, "udp"),
                }

            if ICMP in response:
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code

                if icmp_type == 3 and icmp_code == 3:
                    return None

                if icmp_type == 3:
                    return {
                        "port": port,
                        "state": "filtered",
                        "protocol": "udp",
                        "service": self.service_id.get_service(port, "udp"),
                    }

            if UDP in response:
                return {
                    "port": port,
                    "state": "open",
                    "protocol": "udp",
                    "service": self.service_id.get_service(port, "udp"),
                    "os": self._detect_os(response[IP].ttl),
                }

            return None

        except ImportError:
            return self._scan_udp_port_socket(ip, port)
        except Exception:
            return self._scan_udp_port_socket(ip, port)

    def _scan_udp_port_socket(self, ip: str, port: int) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"", (ip, port))

            try:
                data, addr = sock.recvfrom(1024)
                return {
                    "port": port,
                    "state": "open",
                    "protocol": "udp",
                    "service": self.service_id.get_service(port, "udp"),
                }
            except socket.timeout:
                return {
                    "port": port,
                    "state": "open|filtered",
                    "protocol": "udp",
                    "service": self.service_id.get_service(port, "udp"),
                }
            finally:
                sock.close()
        except Exception:
            return None

    def _format_eta(self, elapsed: float, completed: int, total: int) -> str:
        if completed == 0:
            return "calculating..."
        rate = completed / elapsed
        remaining = (total - completed) / rate
        if remaining < 60:
            return f"{remaining:.0f}s"
        return f"{remaining / 60:.1f}m"

    def scan_tcp(
        self, ip: str, ports: List[int], verbose: bool = False
    ) -> List[Dict]:
        results = []
        total_ports = len(ports)
        start_time = time.time()

        if self.socket_only:
            scan_func = self._scan_tcp_port_socket
            max_threads = self.threads
        else:
            scan_func = self._scan_tcp_port_scapy
            max_threads = min(self.threads, 20) if os.name == "nt" else self.threads

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(scan_func, ip, port): port for port in ports
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_port):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception:
                    pass

                elapsed = time.time() - start_time
                progress = int((completed / total_ports) * 100)
                bar_len = 30
                filled = int(bar_len * completed / total_ports)
                bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
                eta = self._format_eta(elapsed, completed, total_ports)
                print(
                    f"\r  {Colors.DIM}[{bar}] {progress}% "
                    f"({completed}/{total_ports}) "
                    f"ETA: {eta}{Colors.RESET}",
                    end="",
                    flush=True,
                )

            print()

        return sorted(results, key=lambda x: x["port"])

    def scan_udp(
        self, ip: str, ports: List[int], verbose: bool = False,
        show_filtered: bool = False,
    ) -> List[Dict]:
        results = []
        total_ports = len(ports)
        start_time = time.time()
        udp_threads = min(self.threads, 50)

        scan_func = (
            self._scan_udp_port_socket
            if (os.name == "nt" or self.socket_only)
            else self._scan_udp_port
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=udp_threads) as executor:
            future_to_port = {
                executor.submit(scan_func, ip, port): port for port in ports
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_port):
                completed += 1
                try:
                    result = future.result()
                    if result:
                        if show_filtered or result["state"] == "open":
                            results.append(result)
                except Exception:
                    pass

                elapsed = time.time() - start_time
                progress = int((completed / total_ports) * 100)
                bar_len = 30
                filled = int(bar_len * completed / total_ports)
                bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
                eta = self._format_eta(elapsed, completed, total_ports)
                print(
                    f"\r  {Colors.DIM}[{bar}] {progress}% "
                    f"({completed}/{total_ports}) "
                    f"ETA: {eta}{Colors.RESET}",
                    end="",
                    flush=True,
                )

            print()

        return sorted(results, key=lambda x: x["port"])

    def scan_all(
        self,
        ip: str,
        ports: List[int],
        tcp: bool = True,
        udp: bool = False,
        verbose: bool = False,
        show_filtered: bool = False,
    ) -> Dict:
        results = {
            "ip": ip,
            "hostname": self._get_hostname(ip),
            "tcp": [],
            "udp": [],
        }

        if tcp:
            results["tcp"] = self.scan_tcp(ip, ports, verbose)

        if udp:
            results["udp"] = self.scan_udp(ip, ports, verbose, show_filtered)

        return results
