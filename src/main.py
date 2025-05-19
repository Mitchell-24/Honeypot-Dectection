import honeypot_detector
import sys

if len(sys.argv) < 2:
    print("Please provide the address of the host as an argument.")
    sys.exit(1)
ip_address = sys.argv[1]


detector = honeypot_detector.HoneypotDetector(ip_address)
detector.scan_all_ports()
detector.test_conpot()