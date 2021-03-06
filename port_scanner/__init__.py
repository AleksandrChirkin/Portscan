from port_scanner.errors import PortScannerError, BadPortRangeError
from port_scanner.scanner import Scanner
from typing import List, Tuple
import re


__all__ = ['Scanner', 'PortScannerError', 'BadPortRangeError', 'scan']


def verify_user_input(port_range: str) -> Tuple[int, int]:
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if not port_range_valid:
        raise BadPortRangeError(port_range)
    try:
        port_start = int(port_range_valid.group(1))
        port_end = int(port_range_valid.group(2))
    except ValueError:
        raise BadPortRangeError(port_range)
    return port_start, port_end


def scan(tcp_only: bool, udp_only: bool, ports: List[str], host: str):
    port_start, port_end = verify_user_input("-".join(ports))
    scanner = Scanner(host, port_start, port_end)
    scanner.start_scan(tcp_only, udp_only)
