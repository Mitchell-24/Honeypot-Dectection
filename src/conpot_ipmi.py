from subprocess import run, CalledProcessError
from scapy.all import *

def raw_rmcp_open_request(pdst):

    # === RMCP Header ===
    rmcp_header = bytes([
        0x06,  # RMCP Version
        0x00,  # Reserved
        0xFF,  # Sequence Number
        0x07   # RMCP Class: ASF/IPMI
    ])

    # === Variant RMCP+ Wrapper (no length field) ===
    auth_type = bytes([0x06])
    payload_type = bytes([0x10])
    session_id = bytes(4)
    sequence_number = bytes(4)
    payload_len = bytes([0x20, 0x00])

    # === Open Session Request Payload (32 bytes) ===
    payload = bytes([
        0x01,       # Message Tag
        0x00,       # Requested Priv Level: Admin
        0x00, 0x00  # Reserved
    ])
    payload += session_id  # Reuse as console session ID

    payload += bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # auth
    payload += bytes([0x01, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # integrity
    payload += bytes([0x02, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])  # privacy

    # === Build final packet ===
    packet = IP(dst=pdst) / UDP(sport=623, dport=623) / Raw(
        load=rmcp_header + auth_type + payload_type + session_id + sequence_number + payload_len + payload
    )
    r: bytes = packet[Raw].load
    print(r.hex(" "))

    sniff = AsyncSniffer(filter="port 623", prn=handle, timeout = 3)
    sniff.start()
    send(packet, count=1)
    sniff.join()

def handle(packet):
    packet.show()


def test(address):
    cmd_info = f"ipmitool -I lanplus -H {address} -p 623 -C3 -U Administrator -P Password mc info"
    cmd_reset_warm = f"ipmitool -I lanplus -H {address} -p 623 -C3 -U Administrator -P Password mc reset warm"
    cmd_selftest = f"ipmitool -I lanplus -H {address} -p 623 -C3 -U Administrator -P Password mc selftest"
    cmd_userlist = f"ipmitool -I lanplus -H {address} -p 623 -C3 -U Administrator -P Password user list"
    
    info = run(cmd_info, shell=True, capture_output=True, timeout=5).stdout
    user_list = run(cmd_userlist, shell=True, capture_output=True, timeout=5).stdout

    #print(info.decode())
    #print(user_list.decode())
    
    ### Command with exploitable bug? If one resets to 
    ###     'cold', one gets the response: 'Sent cold reset command to MC'
    ###     'warm', one gets the response: 'MC reset command failed: Invalid command'
    try:

        run(cmd_reset_warm, shell=True, capture_output=True, check=True, timeout=5)

    except CalledProcessError as e:
        err_msg = e.stderr.decode()
        if err_msg == "MC reset command failed: Invalid command\n":
            return True


    ### Example where conpot just returns: 'I have no fucking clue'
    try:

        run(cmd_selftest, shell=True, capture_output=True, check=True, timeout=5)

    except CalledProcessError as e:
        err_msg = e.stderr.decode()
        if err_msg == "Bad response: (Invalid command)\n":
            return True
    
    return False

if __name__ == "__main__":
    raw_rmcp_open_request("localhost")