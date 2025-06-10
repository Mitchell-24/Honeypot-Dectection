import logging
import binascii, socket

frame = binascii.unhexlify("000000000005002b0e0200")
port = 502

def test(address):
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((address, port))
        s.sendall(frame)
        data = s.recv(1024)
        if data:
            return False
        else:
            #print("Modbus signature found.")
            return True
    except socket.error as e:
        #print(f"Socket error: {e}")
        return False
    finally:
        s.close()
