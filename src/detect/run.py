from detect.scans import *
from detect.core.base_scan import ScanMeta


def main():
    for scan_cls in ScanMeta.SCANS.values():
        result = scan_cls().run()
        result.pretty_print()
