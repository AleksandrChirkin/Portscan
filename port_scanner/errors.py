class PortScannerError(Exception):
    message: str


class BadPortRangeError(PortScannerError):
    def __init__(self, port_range):
        self.message = f'Bad port range {port_range}'
