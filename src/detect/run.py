from detect.scans import *
from detect.core.base_scan import ScanMeta


def main():
    for scan_cls in ScanMeta.SCANS.values():
        for conclusion in scan_cls().run():
            conclusion.pretty_print()
