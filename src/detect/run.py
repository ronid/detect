from detect.scans import *
from detect.core.base_scan import ScanMeta
import sys


def scan_network():
    for scan_cls in ScanMeta.NETWORK_SCANS.values():
        result = scan_cls().run()
        result.pretty_print()


def scan_host():
    host = sys.argv[1]
    for scan_cls in ScanMeta.HOST_SCANS.values():
        result = scan_cls().run(target=host)
        result.pretty_print()
