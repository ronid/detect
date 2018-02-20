import logbook
from detect.scans import *
from detect.core.base_scan import ScanMeta
import sys


def scan_network():
    subnet = sys.argv[1]
    result = LANIPScan()._run(subnet=subnet)
    result.pretty_print()


def scan_wan_network():
    subnet = sys.argv[1]
    result = WANIPScan()._run(subnet=subnet)
    result.pretty_print()


def scan_host():
    host = sys.argv[1]
    log_handler = logbook.StderrHandler()
    with log_handler.applicationbound():
        for scan_cls in ScanMeta.HOST_SCANS.values():
            result = scan_cls()._run(target=host)
            result.pretty_print()


