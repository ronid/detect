import logbook
from detect.scans import *
from detect.core.base_scan import ScanMeta
import sys


def scan_network():
    for scan_cls in ScanMeta.NETWORK_SCANS.values():
        result = scan_cls()._run()
        result.pretty_print()


def scan_host():
    host = sys.argv[1]
    log_handler = logbook.StderrHandler()
    with log_handler.applicationbound():
        for scan_cls in ScanMeta.HOST_SCANS.values():
            result = scan_cls()._run(target=host)
            result.pretty_print()
