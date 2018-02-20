import inspect
import sys

import logbook
import pyprinter
from detect.core.base_scan import ScanMeta
from detect.scans import *


def scan_network():
    subnet = sys.argv[1]
    result = LANIPScan()._run(subnet=subnet)
    result.pretty_print()


def scan_wan_network():
    subnet = sys.argv[1]
    result = WANIPScan()._run(subnet=subnet)
    result.pretty_print()


def scan():
    subnet = sys.argv[1]
    log_handler = logbook.StderrHandler()
    with log_handler.applicationbound():
        for scan_cls in ScanMeta.NETWORK_SCANS.values():
            result = scan_cls()._run(subnet=subnet)
            result.pretty_print()


def scan_host():
    host = sys.argv[1]
    kwargs = dict()
    for arg in sys.argv[2:]:
        key, value = arg.split('=')
        kwargs[key.strip()] = value
    log_handler = logbook.StderrHandler()
    with log_handler.applicationbound():
        for scan_cls in ScanMeta.HOST_SCANS.values():
            result = scan_cls()._run(target=host, **kwargs)
            result.pretty_print()


def print_help():
    printer = pyprinter.get_printer(width_limit=3000)
    printer.write_title('Subnet scans', title_color=printer.RED)
    for scan_name, scan_cls in ScanMeta.NETWORK_SCANS.items():
        _print_scan(printer, scan_name, scan_cls)
    printer.write_title('Host scans', title_color=printer.RED)
    for scan_name, scan_cls in ScanMeta.HOST_SCANS.items():
        _print_scan(printer, scan_name, scan_cls)


def _print_scan(printer, scan_name, scan_cls):
    printer.write_line(printer.CYAN + scan_name)
    printer.write_line(scan_cls.run.__doc__)
    printer.write_line(printer.WHITE + 'Default values: ')
    for param, value in inspect.signature(scan_cls.run).parameters.items():
        if param in ('self, kwargs'):
            continue
        printer.write_aligned(key=param, value=value.default, key_color=printer.GREEN, align_size=10)
    printer.write_line()
    printer.write_line()
