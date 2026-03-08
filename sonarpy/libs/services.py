from typing import List, Optional


class ServiceIdentifier:

    TCP_SERVICES = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        119: "nntp",
        123: "ntp",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        161: "snmp",
        162: "snmptrap",
        179: "bgp",
        194: "irc",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        514: "syslog",
        515: "printer",
        520: "rip",
        587: "submission",
        631: "ipp",
        636: "ldaps",
        873: "rsync",
        993: "imaps",
        995: "pop3s",
        1080: "socks",
        1194: "openvpn",
        1433: "ms-sql-s",
        1434: "ms-sql-m",
        1521: "oracle",
        1723: "pptp",
        1883: "mqtt",
        2049: "nfs",
        2082: "cpanel",
        2083: "cpanel-ssl",
        2181: "zookeeper",
        2222: "ssh-alt",
        2375: "docker",
        2376: "docker-ssl",
        3000: "nodejs",
        3128: "squid",
        3306: "mysql",
        3389: "ms-wbt-server",
        3690: "svn",
        4369: "epmd",
        4443: "https-alt",
        5000: "upnp",
        5432: "postgresql",
        5672: "amqp",
        5900: "vnc",
        5901: "vnc-1",
        5984: "couchdb",
        6379: "redis",
        6443: "kubernetes",
        6667: "irc",
        7001: "weblogic",
        7002: "weblogic-ssl",
        8000: "http-alt",
        8008: "http-alt",
        8080: "http-proxy",
        8081: "http-alt",
        8443: "https-alt",
        8888: "http-alt",
        9000: "cslistener",
        9042: "cassandra",
        9090: "prometheus",
        9200: "elasticsearch",
        9300: "elasticsearch",
        9418: "git",
        9999: "abyss",
        10000: "webmin",
        11211: "memcached",
        15672: "rabbitmq-mgmt",
        27017: "mongodb",
        27018: "mongodb",
        28017: "mongodb-web",
        50000: "db2",
        50070: "hadoop-namenode",
        50075: "hadoop-datanode",
        88: "kerberos",
        113: "ident",
        199: "smux",
        554: "rtsp",
        902: "vmware-auth",
        912: "vmware-auth-alt",
        1025: "nfs-or-iis",
        1720: "h323q931",
        1900: "upnp-tcp",
        2000: "cisco-sccp",
        2121: "ftp-alt",
        3268: "globalcatLDAP",
        3269: "globalcatLDAPssl",
        4848: "glassfish",
        5060: "sip",
        5222: "xmpp-client",
        5269: "xmpp-server",
        5985: "winrm",
        5986: "winrm-ssl",
        7199: "cassandra-jmx",
        8009: "ajp13",
        8180: "http-alt",
        8443: "https-alt",
        9443: "https-alt",
        10250: "kubelet",
        10443: "https-alt",
    }

    UDP_SERVICES = {
        53: "domain",
        67: "dhcp-server",
        68: "dhcp-client",
        69: "tftp",
        123: "ntp",
        137: "netbios-ns",
        138: "netbios-dgm",
        161: "snmp",
        162: "snmptrap",
        389: "ldap",
        500: "isakmp",
        514: "syslog",
        520: "rip",
        1194: "openvpn",
        1434: "ms-sql-m",
        1604: "citrix",
        1701: "l2tp",
        1812: "radius",
        1813: "radius-acct",
        1900: "upnp",
        2049: "nfs",
        4500: "ipsec-nat-t",
        5060: "sip",
        5353: "mdns",
        5683: "coap",
        6881: "bittorrent",
        8125: "statsd",
        9999: "abyss",
        10161: "snmptls",
        33434: "traceroute",
    }

    TOP_TCP_PORTS = [
        80,
        443,
        22,
        21,
        25,
        53,
        110,
        143,
        993,
        995,
        3306,
        3389,
        8080,
        445,
        139,
        135,
        23,
        8443,
        587,
        465,
        5432,
        27017,
        6379,
        8000,
        1433,
        389,
        636,
        161,
        162,
        179,
        5900,
        1080,
        8888,
        9090,
        9200,
        2049,
        111,
        5672,
        15672,
        11211,
        6443,
        2375,
        1883,
        9042,
        5984,
        4369,
        873,
        514,
        1521,
        1723,
    ]

    TOP_UDP_PORTS = [
        53,
        161,
        123,
        137,
        138,
        500,
        1900,
        5353,
        67,
        68,
        69,
        514,
        162,
        389,
        1194,
        4500,
        1701,
        1812,
        1813,
        520,
        2049,
        5060,
        1434,
        1604,
        5683,
        6881,
        8125,
        9999,
        10161,
        33434,
    ]

    MAX_TOP_TCP_PORTS = 100
    MAX_TOP_UDP_PORTS = 30

    @classmethod
    def get_service(cls, port: int, protocol: str = "tcp") -> str:
        if protocol.lower() == "tcp":
            result = cls.TCP_SERVICES.get(port)
        elif protocol.lower() == "udp":
            result = cls.UDP_SERVICES.get(port)
        else:
            return "unknown"

        if result:
            return result

        try:
            import socket

            return socket.getservbyport(port, protocol.lower())
        except OSError:
            return "unknown"

    @classmethod
    def get_port(cls, service: str, protocol: str = "tcp") -> Optional[int]:
        services = cls.TCP_SERVICES if protocol.lower() == "tcp" else cls.UDP_SERVICES
        for port, svc in services.items():
            if svc.lower() == service.lower():
                return port
        return None

    @classmethod
    def is_common_port(cls, port: int, protocol: str = "tcp") -> bool:
        if protocol.lower() == "tcp":
            return port in cls.TCP_SERVICES
        elif protocol.lower() == "udp":
            return port in cls.UDP_SERVICES
        return False

    @classmethod
    def get_all_common_ports(cls, protocol: str = "tcp") -> list:
        if protocol.lower() == "tcp":
            return sorted(cls.TCP_SERVICES.keys())
        elif protocol.lower() == "udp":
            return sorted(cls.UDP_SERVICES.keys())
        return []

    @classmethod
    def get_top_ports(cls, n: int = 20, protocol: str = "tcp") -> List[int]:
        if protocol.lower() == "udp":
            max_ports = cls.MAX_TOP_UDP_PORTS
            priority = list(cls.TOP_UDP_PORTS)
            remaining = sorted(
                p for p in cls.UDP_SERVICES.keys() if p not in cls.TOP_UDP_PORTS
            )
        else:
            max_ports = cls.MAX_TOP_TCP_PORTS
            priority = list(cls.TOP_TCP_PORTS)
            remaining = sorted(
                p for p in cls.TCP_SERVICES.keys() if p not in cls.TOP_TCP_PORTS
            )

        all_ports = priority + remaining

        if n > max_ports:
            from .colors import Colors

            print(
                f"{Colors.YELLOW}[*] --top-ports max for {protocol.upper()} "
                f"is {max_ports}, using {max_ports} ports{Colors.RESET}"
            )
            print(f"{Colors.DIM}    Use -p 1-65535 for a full scan{Colors.RESET}")
            n = max_ports

        return sorted(all_ports[:n])
