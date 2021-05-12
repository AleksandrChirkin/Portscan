import socket
from threading import Lock, Thread
from queue import Queue


class Scanner:
    def __init__(self, host: str, port_start: int, port_end: int):
        self.host = host
        self.port_range = range(port_start, port_end + 1)
        self.ports_queue = Queue()
        self.print_lock = Lock()

    def start_scan(self, tcp_only: bool, udp_only: bool):
        threads = []
        for port in self.port_range:
            if not udp_only or tcp_only:
                self.ports_queue.put(port)
                t = Thread(target=self.thread_scan, args=(self.scan_tcp_port,))
                threads.append(t)
            if not tcp_only or udp_only:
                self.ports_queue.put(port)
                t = Thread(target=self.thread_scan, args=(self.scan_udp_port,))
                threads.append(t)
        for thread in threads:
            thread.start()
        self.ports_queue.join()

    def thread_scan(self, scan_func):
        port = self.ports_queue.get()
        scan_func(port)
        self.ports_queue.task_done()

    def scan_udp_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                               socket.IPPROTO_UDP) as sock:
                sock.settimeout(1)
                sock.sendto(b'ping', (self.host, port))
                sock.recvfrom(1024)
            protocol = self.get_protocol(port, 'udp')
            print(f'UDP {port} {protocol}')
        except (socket.timeout, OSError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'UDP {port}: Not enough rights')

    def scan_tcp_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                sock.connect((self.host, port))
            protocol = self.get_protocol(port, 'tcp')
            with self.print_lock:
                print(f'TCP {port} {protocol}')
        except (socket.timeout, OSError, ConnectionRefusedError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(port: int, transport: str) -> str:
        try:
            return socket.getservbyport(port, transport).upper()
        except OSError:
            return ''
