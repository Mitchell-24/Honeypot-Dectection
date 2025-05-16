import socket

import conpot_S7
import conpot_iec104
import conpot_modbus


class HoneypotDetector:

    def __init__(self, host_address):
        """
        Constructs a HoneypotDetector
        :param host_address: the IP address of the target host.
        """
        self.host_address = host_address

        # NOTE: maybe different honeypots use different ports for a protocol,
        # then we would need to check specifically per honeypot.
        self.S7_port_open = False
        self.IEC104_port_open = False
        self.Modbus_port_open = False
        self.check_ports()

    def check_ports(self):
        """
        Checks which ports the host has open.
        """
        print("Checking the host for open ports...")
        self.S7_port_open = self.test_port_open(102, "S7")
        self.IEC104_port_open = self.test_port_open(2404, "IEC104")
        self.Modbus_port_open = self.test_port_open(502, "Modbus")

    def test_port_open(self, port, protocol):
        """
        Tests if the host has a port open.
        :param port: The port to be tested
        :param protocol: The protocol that usually uses the port.
        :return: True if the port is open, False otherwise.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((self.host_address, port))
        s.close()
        if result == 0:
            print("Found port " + str(port) + " open: " + protocol + " protocol.")
        return result == 0

    def test_conpot(self):
        """
        Determines if the host is running Conpot based which signatures can be elicited.
        """
        print("\nTesting if the host is a Conpot instance...")

        if self.S7_port_open:
            try: S7 = conpot_S7.test(self.host_address)
            except: S7 = False
        else: S7 = False
        print("Found S7 signature.") if S7 else None

        if self.IEC104_port_open:
            try: IEC104 = conpot_iec104.test(self.host_address)
            except: IEC104 = False
        else: IEC104 = False
        print("Found IEC104 signature.") if IEC104 else None

        if self.Modbus_port_open:
            try: Modbus = conpot_modbus.test(self.host_address)
            except: Modbus = False
        else: Modbus = False
        print("Found Modbus signature.") if Modbus else None

        # ATG = TODO
        # print("Found ATG signature.") if ATG else None

        if S7 or IEC104 or Modbus:
            print("The host is definitely a Conpot instance.")
        # else if ATG:
        #     print("The host could be a Conpot instance.")
        else:
            print("Unlikely that the host is a Conpot instance.")
