import socket
import threading
from port_scanner import UnknownHostError


class Scanner:
    def __init__(self, host: str, port_start: int, port_end: int):
        try:
            self.host = socket.gethostbyname(host)
        except socket.gaierror:
            raise UnknownHostError(host)
        self.port_range = range(port_start, port_end + 1)
        self.print_lock = threading.Lock()

    def scan(self, tcp_only: bool, udp_only: bool):
        if not udp_only or tcp_only:
            for port in self.port_range:
                t = threading.Thread(target=self.scan_tcp_port, args=(port,))
                t.start()
        if not tcp_only or udp_only:
            for port in self.port_range:
                t = threading.Thread(target=self.scan_udp_port, args=(port,))
                t.start()

    def scan_udp_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                               socket.IPPROTO_UDP) as sock,\
                    socket.socket(socket.AF_INET,
                                  socket.SOCK_RAW,
                                  socket.IPPROTO_UDP) as receiver:
                receiver.settimeout(3)
                sock.sendto(b'', (self.host, port))
                data = receiver.recvfrom(1024)[0]
                with self.print_lock:
                    print(f'UDP {port}')
        except socket.timeout:
            pass
        except PermissionError:
            with self.print_lock:
                print(f'UDP {port}: Not enough rights')

    def scan_tcp_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                sock.connect((self.host, port))
                with self.print_lock:
                    print(f'TCP {port} {self.get_protocol(port)}')
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        except PermissionError:
            with self.print_lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(port: int):
        if port == 123:
            return 'NTP'
        if port == 53:
            return 'DNS'
        if port in [25, 465]:
            return 'SMTP'
        if port in [110, 995]:
            return 'POP3'
        if port in [143, 993]:
            return 'IMAP'
        if port == 80:
            return 'HTTP'
        if port == 443:
            return 'HTTPS'
        return ''
