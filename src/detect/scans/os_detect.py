import nmap
import pyprinter

from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult


class OSDetectScanResult(object):
    def __init__(self, os, vendor, accuracy):
        self.os = os
        self.vendor = vendor
        self.accuracy = accuracy

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()
        printer.write_line(f'{printer.WHITE}{self.os} {printer.CYAN}({self.vendor}) {printer.GREEN}{self.accuracy}%{printer.NORMAL}')


class OSDetectScan(Scan):
    """
    Scan trites to identify target os using nmap os detection.
    """
    NAME = 'OS Detect Scan'

    def run(self, target='127.0.0.1'):
        """
        Performs nmap os detect against target given.
        Nmap sends a series of TCP and UDP packets to the remote host and examines practically every bit in the
        responses. After performing dozens of tests such as TCP ISN sampling, TCP options support and ordering,
        IP ID sampling, and the initial window size check, Nmap compares the results to its
        nmap-os-db database of more than 2,600 known OS fingerprints

        :param target: name/IP of target.
        :return: Scan result that contains a list of all possible os match.
        """
        nm = nmap.PortScanner()
        self.logger.info('performing nmap os detection')
        nm.scan(target, arguments='-O')
        results = []
        self.logger.info('{} os matches were detected.'.format(len(nm[target].get('osmatch', []))))
        for match in nm[target].get('osmatch', []):
            results.append(OSDetectScanResult(os=match['name'],
                                              vendor=match['osclass'][0]['vendor'],
                                              accuracy=match['accuracy']))
        return ScanResult(self.NAME, results)
