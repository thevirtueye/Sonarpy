import socket
import ssl
from typing import Optional, Dict


class BannerGrabber:

    HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 8008}
    HTTPS_PORTS = {443, 8443, 4443, 9443}

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def _grab_http(self, ip: str, port: int, use_ssl: bool = False) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)

            sock.connect((ip, port))

            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: Sonarpy/5.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.send(request.encode())

            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            for line in response.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()

            if response:
                first_line = response.splitlines()[0]
                if "HTTP" in first_line:
                    return first_line.strip()

            return None
        except Exception:
            return None

    def _grab_generic(self, ip: str, port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            try:
                sock.send(b"\r\n")
            except Exception:
                pass

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            if banner:
                banner = "".join(
                    c for c in banner if c.isprintable() or c in "\n\r\t"
                )
                for line in banner.splitlines():
                    line = line.strip()
                    if line and len(line) > 2:
                        return line[:200]

            return None
        except Exception:
            return None

    def _grab_ssl_info(self, ip: str, port: int) -> Optional[str]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        cn = subject.get("commonName", "")
                        return f"SSL: {cn}" if cn else None

            return None
        except Exception:
            return None

    def grab(self, ip: str, port: int) -> Optional[str]:
        if port in self.HTTP_PORTS:
            return self._grab_http(ip, port, use_ssl=False)

        if port in self.HTTPS_PORTS:
            banner = self._grab_http(ip, port, use_ssl=True)
            if not banner:
                banner = self._grab_ssl_info(ip, port)
            return banner

        return self._grab_generic(ip, port)

    def grab_all(self, ip: str, ports: list) -> Dict[int, Optional[str]]:
        results = {}
        for port in ports:
            results[port] = self.grab(ip, port)
        return results
