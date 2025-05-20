import socket
import time

PORT = 10001
TIMEOUT = 10


KNOWN_COMMANDS = [
    b'\x01I20100\r',
    b'\x01I20200\r',
    b'\x01I20300\r',
    b'\x01I20400\r',
    b'\x01I20500\r',
]


UNKNOWN_COMMANDS = [
    b'\x01I20600\r',
    b'\x01I90900\r',
    b'\x01I90800\r',
    b'\x01X00000\r',
    b'\x01I20700\r'
]

SIGNATURE_PATTERNS = [
    b'9999FF1B',       
    b'\n\n\n\n',        
    b'Gilbarco',        
    b'Serial'           
]

def test(address):
    """
    Tests if the host at given address behaves like a GasPot honeypot.
    :param address: IP or hostname
    :return: True if GasPot signatures are detected, False otherwise
    """
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((address, PORT))
        print(f"[+] Connected to {address}:{PORT}")

        all_commands = KNOWN_COMMANDS + UNKNOWN_COMMANDS
        matched_signatures = 0
        responses = []

        for cmd in all_commands:
            s.send(cmd)
            time.sleep(0.1)  
            try:
                data = s.recv(4096)
                responses.append((cmd, data))


                if any(sig in data for sig in SIGNATURE_PATTERNS):
                    matched_signatures += 1

            except socket.timeout:
                responses.append((cmd, b'[No Response - Timeout]'))

        s.close()

        print(f"\n[✓] Completed scan. Matched signatures: {matched_signatures}")
        for cmd, resp in responses:
            clean_resp = resp.decode("utf-8", errors="ignore").replace("\n", "\\n")
            print(f"↪ Command: {cmd} → Response: {clean_resp[:100]}")

        return matched_signatures > 0

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return False