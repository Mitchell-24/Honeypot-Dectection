import socket

import conpot_S7
import conpot_iec104
import conpot_ipmi
import conpot_modbus

class HoneypotDetector:

    def __init__(self, host_address):
        """
        Constructs a HoneypotDetector
        :param host_address: the IP address of the target host.
        """
        self.host_address = host_address
        self.open_ports = {}
        self.checked_ports = False

    def scan_all_ports(self):
        """
        Scans all TCP + UDP ports on the host to check if they are open.
        Prints the number of open ports and if this implies the host is a honeypot.
        """
        print("Scanning all ports on the host...")
        for i in range(1, 65535):
            TCP_protocol = ""
            UDP_protocol = ""
            if i == 102:
                TCP_protocol = "S7"
            elif i == 2404:
                TCP_protocol = "IEC104"
            elif i == 623:
                UDP_protocol = "IPMI"
            elif i == 502:
                TCP_protocol = "Modbus"
            self.open_ports["TCP-" + str(i)] = self.test_TCP_port_open(i, TCP_protocol)
            self.open_ports["UDP-" + str(i)] = self.test_UDP_port_open(i, UDP_protocol)
        count = 0
        ports = self.open_ports.keys()
        for port in ports:
            if self.open_ports[port]:
                count += 1
        if count > 30:
            print("The host has " + str(count) + " ports open. Based on this, it is likely that the host is a honeypot")
        elif count > 10:
            print("The host has " + str(count) + " ports open. Based on this, it is possible that the host is a honeypot")
        else:
            print("The host has " + str(count) + " ports open. Based on this, it is unlikely that the host is a honeypot")
        self.checked_ports = True
        
    def check_ports(self):
        """
        Checks which ports ICS the host has open.
        """
        print("Checking the host for open ICS ports...")

        self.open_ports["TCP-102"] = self.test_TCP_port_open(102, "S7")
        self.open_ports["TCP-2404"] = self.test_TCP_port_open(2404, "IEC104")
        self.open_ports["UDP-623"] = self.test_UDP_port_open(623, "IPMI")
        self.open_ports["TCP-502"] = self.test_TCP_port_open(502, "Modbus")
        self.checked_ports = True

    def test_TCP_port_open(self, port, protocol):
        """
        Tests if the host has a TCP port open.
        :param port: The TCP port to be tested
        :param protocol: The protocol that usually uses the port.
        :return: True if the port is open, False otherwise.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(3)
        result = s.connect_ex((self.host_address, port))
        s.close()
        if result == 0:
            if protocol != "":
                print("Found TCP port " + str(port) + " open: " + protocol + " protocol.")
            else:
                print("Found TCP port " + str(port) + " open")
        return result == 0

    def test_UDP_port_open(self, port, protocol):
        """
        Tests if the host has a UDP port open.
        :param port: The UDP port to be tested
        :param protocol: The protocol that usually uses the port.
        :return: True if the port is open, False otherwise.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        result = s.connect_ex((self.host_address, port))
        s.close()
        if result == 0:
            if protocol != "":
                print("Found UDP port " + str(port) + " open: " + protocol + " protocol.")
            else:
                print("Found UDP port " + str(port) + " open")
        return result == 0

    def test_conpot(self):
        """
        Determines if the host is running Conpot based which signatures can be elicited.
        """
        if not self.checked_ports:
            self.check_ports()
        print("\nTesting if the host is a Conpot instance...")

        if self.open_ports["TCP-102"]:
            try: S7 = conpot_S7.test(self.host_address)
            except: S7 = False
        else: S7 = False
        print("Found S7 signature.") if S7 else None

        if self.open_ports["TCP-2404"]:
            try: IEC104 = conpot_iec104.test(self.host_address)
            except: IEC104 = False
        else: IEC104 = False
        print("Found IEC104 signature.") if IEC104 else None

        if self.open_ports["UDP-623"]:
            try: IPMI = conpot_ipmi.test(self.host_address)
            except: IPMI = False
        else: IPMI = False
        print("Found IPMI signature.") if IPMI else None

        if self.open_ports["TCP-502"]:
            try: modbus = conpot_modbus.test(self.host_address)
            except: modbus = False
        else: modbus = False
        print("Found Modbus signature.") if modbus else None

        # ATG = TODO
        # print("Found ATG signature.") if ATG else None


        if S7 or IEC104 or IPMI or modbus:
            print("The host is definitely a Conpot instance.")
        # else if ATG:
        #     print("The host could be a Conpot instance.")
        else:
            print("Unlikely that the host is a Conpot instance.")
