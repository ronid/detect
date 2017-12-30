import nmap

from detect.core.base_scan import Scan
from detect.core.scan_result import ScanResult


class OSDetectScan(Scan):
    NAME = 'OS Detect Scan'

    def run(self, host='127.0.0.1', start_port=22, end_port=443):
        nm = nmap.PortScanner()
        res = nm.scan(host, '{}-{}'.format(start_port, end_port))
        self.logger.info('Executing command line {}'.format(res['nmap']['command_line']))

        detect = dict()
        detect['hostname'] = [match['name'] for match in res['scan'][host]['hostnames']]
        yield ScanResult(self.NAME, res['nmap']['scanstats']['elapsed'], **detect)
