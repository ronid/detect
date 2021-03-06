import pyprinter
from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult
from scapy.all import srp, ARP, Ether
import scapy

class LANIPScanResult(object):
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()
        printer.write_line(f'{printer.YELLOW}{self.mac} {printer.DARK_YELLOW}{self.ip}')


class LANIPScan(Scan):
    """
    Scans IP & MAC addresses in the local network
    """
    NAME = 'LAN IP Scan'
    TIMEOUT = 1


    def run(self, interface='vmnet2', subnet='192.168.2.0/24',**kwargs):
        """
        Sends arp queries to a given subnet by using Scapy's send-receive function.
        The function sets the MAC destination in the scapy packet to be broadcast in order to get answers from
        all the entities in the local network. It sends 'who has IP x.x.x.x' for each one of the addresses in a given subnet
        and then extracts the MAC & IP addresses from each one of the responses.
        :param interface: name of the interface to scan.
        :param subnet: ip range to scan
        :return: Scan result that contains all the MAC & IP addresses in the local network
        """
        interface = [eth['name'] for eth in scapy.arch.windows.get_windows_if_list() if interface in eth['name'].lower()][0]

        results = []
        responses, no_responses = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=subnet), iface=interface,
                                      timeout=self.TIMEOUT, verbose=0)
        for request, reply in responses:
            results.append(LANIPScanResult(reply.hwsrc, reply.psrc))

        return ScanResult(self.NAME, results)
