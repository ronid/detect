import datetime as dt
import socket

from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult


class PortScanResult(object):
    def __init__(self, port_number, protocol, is_open):
        self.port_number = port_number
        self.protocol = protocol
        self.is_open = is_open


class PortScan(Scan):
    NAME = 'Port Scan'

    def run(self, host='127.0.0.1', start_port=22, end_port=443):
        start_port = start_port if isinstance(start_port, int) else int(start_port)
        end_port = end_port if isinstance(end_port, int) else int(end_port)

        conclusions = []
        start = dt.datetime.now()
        for port in range(start_port, end_port):
            self.logger.info('Trying to establish UDP/TCP connection on port {}'.format(port))
            for protocol in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(socket.AF_INET, protocol)
                result = sock.connect_ex((host, port))
                conclusions.append(PortScanResult(port_number=port,
                                                  protocol='TCP' if protocol == socket.SOCK_STREAM else 'UDP',
                                                  is_open=True if result == 0 else False))
                sock.close()

        end = dt.datetime.now()
        yield ScanResult(self.NAME, end-start, conclusions=conclusions, columns=['port_number', 'protocol', 'is_open'])
