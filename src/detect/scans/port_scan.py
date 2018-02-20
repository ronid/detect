import socket

import pyprinter
from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult

_PROTOCOLS = {
    socket.SOCK_STREAM: 'TCP',
}


class PortScanResult(object):
    def __init__(self, port_number, protocol, is_open):
        self.port_number = port_number
        self.protocol = protocol
        self.is_open = is_open

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()
        status_color = printer.GREEN if self.is_open else printer.RED
        line = f'{self.port_number} {self.protocol} {status_color}{self.is_open}{printer.NORMAL}'
        printer.write_line(line)


class PortScan(Scan):
    """
    Scan for open ports on target between start port and end port.
    """
    NAME = 'Port Scan'

    def run(self, target='127.0.0.1', ports='441-443', **kwargs):
        """
        Runs port scan against given host.

        :param target: IP or name of target.
        :param ports: list of port ranges as strings.
        :return: ScanResult object with list of ports and their status.
        """

        conclusions = []
        for port_ranges in ports.split(','):
            start_port, end_port = port_ranges.split('-')
            start_port = start_port if isinstance(start_port, int) else int(start_port)
            end_port = end_port if isinstance(end_port, int) else int(end_port)
            for port in range(start_port, end_port + 1):
                self.logger.info('Trying to establish UDP/TCP connection on port {}'.format(port))
                for protocol in _PROTOCOLS.keys():
                    sock = socket.socket(socket.AF_INET, protocol)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        self.logger.info('Port {} is {} open'.format(port, _PROTOCOLS.get(protocol)))
                    conclusions.append(PortScanResult(port_number=port,
                                                      protocol=_PROTOCOLS.get(protocol),
                                                      is_open=True if result == 0 else False))
                    sock.close()

        return ScanResult(self.NAME, conclusions=conclusions)
