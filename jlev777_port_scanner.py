import unittest
import nmap

class NmapScannerTest(unittest.TestCase):
    def setUp(self):
        self.scanner = nmap.PortScanner()

    def test_scan(self):
        ip_addr = input("Enter the IP address to scan: ")
        resp = input("""\nEnter the type of scan you want to perform:
            1) SYN ACK Scan
            2) UDP Scan
            3) Comprehensive Scan\n""")
        
        print("\nRunning Nmap Scan Test...")
        print("IP Address: ", ip_addr)
        print("Selected Scan Type: ", resp)
        
        self.assertIn(resp, ['1', '2', '3'])
        
        if resp == '1':
            result = self.scanner.scan(ip_addr, '1-1024', '-v -sS')
            self.assertEqual(result['nmap']['scanstats']['uphosts'], '1')
            protocols = self.scanner[ip_addr].all_protocols()
            self.assertIn('tcp', protocols)
            open_ports = sorted(self.scanner[ip_addr]['tcp'].keys())
            self.assertIsInstance(open_ports, list)
            print("Open Ports: ", open_ports)
        elif resp == '2':
            result = self.scanner.scan(ip_addr, '1-1024', '-v -sU')
            self.assertEqual(result['nmap']['scanstats']['uphosts'], '1')
            protocols = self.scanner[ip_addr].all_protocols()
            self.assertIn('udp', protocols)
            open_ports = sorted(self.scanner[ip_addr]['udp'].keys())
            self.assertIsInstance(open_ports, list)
            print("Open Ports: ", open_ports)
        elif resp == '3':
            result = self.scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
            self.assertEqual(result['nmap']['scanstats']['uphosts'], '1')
            protocols = self.scanner[ip_addr].all_protocols()
            self.assertIn('tcp', protocols)
            open_ports = sorted(self.scanner[ip_addr]['tcp'].keys())
            self.assertIsInstance(open_ports, list)
            print("Open Ports: ", open_ports)

if __name__ == "__main__":
    unittest.main()
