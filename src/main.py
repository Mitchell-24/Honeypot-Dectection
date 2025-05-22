import honeypot_detector
import sys

if len(sys.argv) < 2:
    print("Please provide the address of the host as an argument.")
    sys.exit(1)
ip_address = sys.argv[-1]

full_scan = False
if sys.argv[1] == "-s":
    full_scan = True

detector = honeypot_detector.HoneypotDetector(ip_address)
detector.scan_ports(full_scan=full_scan)
detector.test_conpot()