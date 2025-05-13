import time
import socket


def test(address):
    """
    Tests if the host has the Conpot S7 signature.
    :param address: The IP address of the host.
    :return: True if the signature is found, False otherwise.
    """
    port = 102
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))

    # Handshake part 1
    s.send(bytes.fromhex('03 00 00 16 11 e0 00 00 00 01 00 c0 01 0a c1 02 01 00 c2 02 01 01'))
    data = s.recv(1024)
    time.sleep(0.05)

    # Handshake part 2
    s.send(bytes.fromhex('03 00 00 19 02 f0 80 32 01 00 00 00 00 00 08 00 00 f0 00 00 01 00 01 01 e0'))
    data2 = s.recv(1024)
    time.sleep(0.05)

    # Diagnostics function
    s.send(bytes.fromhex(
        '03 00 00 21 02 f0 80 32 07 00 00 01 00 00 08 00 08 00 01 12 04 11 44 01 00 ff 09 00 04 00 1c 00 00'))
    data3 = s.recv(1024)

    s.close()

    if "Mouser Factory" in str(data3) and "88111222" in str(data3):
        return True
    return False
