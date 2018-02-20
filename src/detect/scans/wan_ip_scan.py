import netifaces
import pyprinter
import scapy
from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult
from scapy.all import Ether, IP, ICMP, srp, ARP


class WANIPScanResult(object):
    def __init__(self, ip):
        self.ip = ip

    def pretty_print(self, printer=None):
        printer = printer or pyprinter.get_printer()
        printer.write_line(f'{printer.YELLOW}{self.ip} exists!')


class WANIPScan(Scan):
    """
    Scans IP addresses outside the local network
    """
    NAME = 'WAN IP Scan'
    TIMEOUT = 1

    def run(self, subnet='8.8.8.8/32', **kwargs):
        """
        Sends ICMP requests to a given subent.
        The function first tries to find the gateway MAC address, by extracting the default gateway IP on the local machine and then
        sending arp request to this IP address. The code extracts the gateway MAC address from the arp response,
        generates ICMP requests (PING) to each one of the addresses in the given subnet and then extracts the IP addresses from the ICMP responses (PING replies).
        The reason the code sends the requests with the gateway MAC address is because we need the requests to be sent to entities outside of the LAN.
        :param subnet: ip range to scan
        :return: Scan result that contains all the existing IP addresses outside the LAN
        """
        results = []
        gateways = netifaces.gateways()
        gateway_ip, ifc_guid = gateways['default'][netifaces.AF_INET]
        ifc = [interface['name'] for interface in
               scapy.arch.windows.get_windows_if_list()
               if interface['guid'] == ifc_guid][0]
        responses, no_responses = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip), iface=ifc,
                                      timeout=self.TIMEOUT, verbose=0)
        if len(responses) != 1:
            return

        arp_request, arp_reply = responses[0]
        gateway_mac = arp_reply.hwsrc

        responses, no_responses = srp(Ether(dst=gateway_mac) / IP(dst=subnet) / ICMP(), iface=ifc,
                                      timeout=self.TIMEOUT, verbose=0)
        for request, reply in responses:
            if reply.payload.payload.fields['type'] == 0 and reply.payload.payload.fields['code'] == 0:
                results.append(WANIPScanResult(reply[IP].src))

        return ScanResult(self.NAME, results)
