import datetime as dt
from scapy.all import *

import pyprinter
from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult


class SnifferScanResult(object):
    def __init__(self, target, is_sniff):
        self.is_sniff = is_sniff
        self.target = target

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()
        status_color = printer.GREEN if self.is_sniff else printer.RED
        line = f'{self.target} is {status_color}{self.is_sniff}{printer.NORMAL}'
        printer.write_line(line)


class SniffScan(Scan):
    """
    Scan if a target sniff right now
    """
    NAME = 'Sniff Scan'

    def run(self, target='127.0.0.1'):
        """
        Runs port scan against given host.

        :param target: IP or name of target.
        :return: ScanResult object with an boolean that say if the target is sniffing or not
        """
        conclusions = []
        ans, uans = srp(Ether(dst='ff:ff:ff:ff:ff:fe')/ARP(pdst=target),timeout=2)
        conclusions.append(SnifferScanResult(target, is_sniff=False if ans.res == [] else True))
        return ScanResult(self.NAME, conclusions=conclusions)
