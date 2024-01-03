# import socket # <-- commented out for this code, but could be used in future code
import time
from scapy.layers.l2 import Ether, ARP
from scapy.all import srp1, conf
import json 
import datetime

class NetworkScanner:
    def __init__(self, ip_address):
        '''Removes the fourth octet of the IP Address (self.net variable) for use in the arp_scan() function
        and creates a filename variable for logging. The file_name variable contains a timestamp 
        for easy sorting and date/time identification of when the scan was performed'''
        # self.interface_name = interface_name # <-- commented out for this code, but could be used in future code to specify the network interface
        # self.host = socket.gethostname() # <-- commented out for this code, but could be used in future code
        self.ip_address = ip_address
        self.net = self.ip_address[0:self.ip_address.rfind('.') + 1]
        self.file_name = f'arp_scan_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json'

    def arp_scan(self):
        '''Scans the network by iterating over each potential host address in range (1 - 254) and returns IP Addresses with associated MAC Addresses.
        The IP addresses and MAC addresses along with timestamps are then recorded in JSON objects which are suitable to be imported into databases, or 
        central logging and analysis tools such as SIEM systems for further security analysis'''
        try:
            with open(self.file_name, 'w') as file:
            # conf.iface = self.interface_name # <-- commented out for this code, but could be used in future code
            # print(f'Using interface: {conf.iface}') # <-- commented out for this code, but could be used in future code
                for port in range(1, 255):
                    ip = f'{self.net}{port}'
                    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip, hwdst='ff:ff:ff:ff:ff:ff')
                    response = srp1(arp_request, timeout=1, verbose=0)
                    if response:
                        result = {
                            'timestamp': timestamp, 
                            'ip_address': response.psrc,
                            'mac_address': response.hwsrc
                        }
                        
                        json_result = json.dumps(result)
                        file.write(f'{json_result}\n')
                        print(json_result)
                    time.sleep(0.5)
        except Exception as e:
            result = print(f'ERROR: {e}')


        print('-' * 50)
        print(f'ARP scan complete. The results were recorded in {self.file_name}')

    def get_network_info(self):
        '''Calls the arp_scan() function'''
        self.arp_scan()

if __name__ == '__main__':
    network_scanner = NetworkScanner('192.0.2.1') # <-- Replace the IP address with your own 
    network_scanner.get_network_info()
