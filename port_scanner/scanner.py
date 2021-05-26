from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM, socket, timeout
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
            with socket(AF_INET, SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(b'hello', (self.host, port))
                response = sock.recv(1024).decode('utf-8')
            protocol = self.get_protocol(response)
            print(f'UDP {port} {protocol}')
        except (timeout, OSError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'UDP {port}: Not enough rights')

    def scan_tcp_port(self, port: int):
        try:
            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                sock.connect((self.host, port))
                try:
                    response = str(sock.recv(1024).decode('utf-8'))
                except timeout:
                    sock.send(f'GET / HTTP/1.1\n\n'.encode())
                    response = sock.recv(1024).decode('utf-8')
            protocol = self.get_protocol(response)
            with self.print_lock:
                print(f'TCP {port} {protocol}')
        except (OSError, ConnectionRefusedError):
            pass
        except PermissionError:
            with self.print_lock:
                print(f'TCP {port}: Not enough rights')

    @staticmethod
    def get_protocol(response: str) -> str:
        if 'HTTP/1.1' in response:
            return 'HTTP'
        if 'SMTP' in response:
            return 'SMTP'
        if 'IMAP' in response:
            return 'IMAP'
        if 'OK' in response:
            return 'POP3'
        return ''
