import datetime as dt
import socket

import pyprinter
from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult

_PROTOCOLS = {
    socket.SOCK_STREAM: 'TCP',
    socket.SOCK_DGRAM: 'UDP'
}


class PortScanResult(object):
    def __init__(self, port_number, protocol, is_open):
        self.port_number = port_number
        self.protocol = protocol
        self.is_open = is_open

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()
        line = '{port} {protocol} {status_color}{is_open}'.format(port=self.port_number,
                                                                  protocol=self.protocol,
                                                                  status_color=printer.GREEN if self.is_open else printer.RED,
                                                                  is_open=self.is_open)
        printer.write_line(line)


class PortScan(Scan):
    """
    Scan for open ports on target between start port and end port.
    """
    NAME = 'Port Scan'

    def run(self, target='127.0.0.1', start_port=441, end_port=443):
        """
        Runs port scan against given host.

        :param target: IP or name of target.
        :param start_port: The first port in ports range.
        :param end_port: The last port in ports range.
        :return: ScanResult object with list of ports and their status.
        """
        start_port = start_port if isinstance(start_port, int) else int(start_port)
        end_port = end_port if isinstance(end_port, int) else int(end_port)

        conclusions = []
        start = dt.datetime.now()
        for port in range(start_port, end_port):
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

        end = dt.datetime.now()
        return ScanResult(self.NAME, end - start, conclusions=conclusions)
