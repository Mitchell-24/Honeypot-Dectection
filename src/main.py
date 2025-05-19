import honeypot_detector

print("Please enter the IP address of the target host: ")
ip_address = input()


detector = honeypot_detector.HoneypotDetector(ip_address)
detector.scan_all_ports()
detector.test_conpot()