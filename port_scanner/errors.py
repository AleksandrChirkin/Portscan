class PortScannerError(Exception):
    message: str


class UnknownHostError(PortScannerError):
    def __init__(self, host):
        self.message = f'Host {host} is unknown'


class BadPortRangeError(PortScannerError):
    def __init__(self, port_range):
        self.message = f'Bad port range {port_range}'
