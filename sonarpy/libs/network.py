import os
import socket
import ipaddress
import subprocess
import concurrent.futures
from typing import List, Optional
from .colors import Colors


class NetworkDiscovery:

    def __init__(self, max_workers: int = 100, timeout: int = 1):
        self.max_workers = max_workers
        self.timeout = timeout
        self._local_ip = self._get_local_ip()

    def _get_local_ip(self) -> Optional[str]:
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except socket.error:
            return None

    def _ping_host(self, ip: str) -> Optional[str]:
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), ip]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 1,
            )

            return ip if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    def _ping_host_scapy(self, ip: str) -> Optional[str]:
        try:
            from scapy.all import IP, ICMP, sr1

            packet = IP(dst=ip) / ICMP()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            return ip if response else None
        except Exception:
            return None

    def discover(
        self, target: str, use_scapy: bool = False, verbose: bool = False
    ) -> List[str]:
        if "/" not in target:
            if verbose:
                print(f"{Colors.DIM}[*] Single target: {target}{Colors.RESET}")
            return [target]

        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            print(f"{Colors.RED}[!] Invalid subnet: {e}{Colors.RESET}")
            return []

        hosts = [str(ip) for ip in network.hosts() if str(ip) != self._local_ip]

        if verbose:
            print(f"{Colors.DIM}[*] Scanning {len(hosts)} hosts...{Colors.RESET}")

        print(
            f"{Colors.YELLOW}[*] Discovering active hosts in {target}...{Colors.RESET}"
        )

        ping_func = self._ping_host_scapy if use_scapy else self._ping_host
        active_hosts = []

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_to_ip = {executor.submit(ping_func, ip): ip for ip in hosts}

            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                completed += 1
                result = future.result()

                if result:
                    active_hosts.append(result)
                    if verbose:
                        print(
                            f"{Colors.GREEN}  [+] Active host: {result}{Colors.RESET}"
                        )

                if not verbose and completed % 50 == 0:
                    progress = int((completed / len(hosts)) * 100)
                    print(
                        f"\r{Colors.DIM}[*] Progress: {progress}%{Colors.RESET}",
                        end="",
                        flush=True,
                    )

        if not verbose:
            print(f"\r{Colors.DIM}[*] Progress: 100%{Colors.RESET}")

        return sorted(active_hosts, key=lambda x: list(map(int, x.split("."))))


class ARPDiscovery:

    def __init__(self, timeout: int = 2):
        self.timeout = timeout

    def discover(self, target: str, verbose: bool = False) -> List[str]:
        try:
            from scapy.all import ARP, Ether, srp

            print(
                f"{Colors.YELLOW}[*] ARP Discovery on {target}...{Colors.RESET}"
            )

            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=self.timeout, verbose=0)[0]

            active_hosts = []
            for sent, received in result:
                active_hosts.append(received.psrc)
                if verbose:
                    print(
                        f"{Colors.GREEN}  [+] {received.psrc} "
                        f"({received.hwsrc}){Colors.RESET}"
                    )

            return active_hosts

        except ImportError:
            print(f"{Colors.RED}[!] Scapy not installed{Colors.RESET}")
            return []
        except PermissionError:
            print(
                f"{Colors.RED}[!] Root privileges required for ARP discovery"
                f"{Colors.RESET}"
            )
            return []
        except Exception as e:
            print(f"{Colors.RED}[!] ARP discovery error: {e}{Colors.RESET}")
            return []
