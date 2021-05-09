from argparse import ArgumentParser
from typing import Any, Dict
import port_scanner


def parse_args() -> Dict[str, Any]:
    parser = ArgumentParser(description='TCP and UDP port scanner')
    parser.add_argument('-t', '--tcp_only', help='Scan only TCP',
                        action='store_true')
    parser.add_argument('-u', '--udp_only', help='Scan only UDP',
                        action='store_true')
    parser.add_argument('-p', '--ports', nargs=2, default=['1', '65535'],
                        metavar='PORT', help='Port range')
    parser.add_argument('host', help='Remote host')
    return parser.parse_args().__dict__


if __name__ == '__main__':
    try:
        args = parse_args()
        port_scanner.scan(**args)
    except port_scanner.PortScannerError as e:
        print(e.message)
        exit(1)
    except KeyboardInterrupt:
        print('\nTerminated.')
