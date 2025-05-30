#!/usr/bin/env python3
"""
Fingerprint completo di Conpot ENIP: esercita tutti i comandi implementati
e identifica al volo il honeypot in base ai valori di default.
"""

import socket
from scapy.all import conf
from enip.enip_tcp import ENIP_TCP, ENIP_RegisterSession
from enip.cip import CIP, CIP_Path

HOST = "127.0.0.1"
PORT = 44818
TIMEOUT = 3

EXPECTED_DEFAULTS = {
    "vendor_id":        1,
    "device_type":     14,
    "product_code":    90,
    "product_revision":2562,
    "serial_number":7079450,
    "product_name":   "1756-L61/B LOGIX5561"
}

def send_enip(sock, cmd, payload):
    """Helper: invia un pacchetto ENIP_TCP e ritorna la risposta parsata"""
    pkt = ENIP_TCP(command_id=cmd, session=session) / payload
    sock.send(bytes(pkt))
    data = sock.recv(8192)
    return ENIP_TCP(data)

def register_session(sock):
    """RegisterSession: invia il comando RegisterSession e ritorna il session handle"""
    req = ENIP_TCP(command_id=0x0065, session=0) / ENIP_RegisterSession()
    sock.send(bytes(req))
    resp = ENIP_TCP(sock.recv(1024))
    return resp.session

def unregister_session(sock, sess):
    """UnregisterSession: invia il comando UnregisterSession"""
    req = ENIP_TCP(command_id=0x0066, session=sess)
    sock.send(bytes(req))
    return ENIP_TCP(sock.recv(1024))

def list_identity(sock, sess):
    """ListIdentity: invia il comando ListIdentity"""
    req = ENIP_TCP(command_id=0x0063, session=sess)
    sock.send(bytes(req))
    return ENIP_TCP(sock.recv(4096))

def get_attr_single(sock, sess, cls, inst, attr):
    """SendRRData / Get_Attribute_Single"""
    path = CIP_Path.make(class_id=cls, instance_id=inst, attribute_id=attr)
    cip = CIP(service=0x0E, path=[path])
    return send_enip(sock, 0x006F, cip)

def set_attr_single(sock, sess, cls, inst, attr, value):
    """SendRRData / Set_Attribute_Single con un UDINT"""
    path = CIP_Path.make(class_id=cls, instance_id=inst, attribute_id=attr)
    cip = CIP(service=0x10, path=[path]) / value.to_bytes(4, 'little')
    return send_enip(sock, 0x006F, cip)

def main():
    conf.verb = 0
    print(f"[*] Connessione a {HOST}:{PORT}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    sock.connect((HOST, PORT))

    global session
    session = register_session(sock)
    print(f"[+] Session handle = {session}")

    # --- ListIdentity + fingerprint check ---
    li = list_identity(sock, session)
    print("[+] ListIdentity response:")
    li.show()

    # Estrai i campi
    vendor   = getattr(li, "vendor_id", None)
    devtype  = getattr(li, "device_type", None)
    pcode    = getattr(li, "product_code", None)
    prev     = getattr(li, "product_revision", None)
    serial   = getattr(li, "serial_number", None)
    raw_name = getattr(li, "product_name", None)

    if isinstance(raw_name, (bytes, bytearray)):
        name = raw_name.rstrip(b"\xff").decode("ascii", errors="ignore")
    else:
        name = raw_name

    # 1) Check immediato su serial_number o device_type
    if serial == EXPECTED_DEFAULTS["serial_number"] or devtype == EXPECTED_DEFAULTS["device_type"]:
        print(f"[!!!] Conpot honeypot detected (serial or device_type match) → "
              f"serial={serial}, device_type={devtype}")
    # 2) Fallback: tutti gli altri insieme
    elif (vendor == EXPECTED_DEFAULTS["vendor_id"]
          and pcode == EXPECTED_DEFAULTS["product_code"]
          and prev == EXPECTED_DEFAULTS["product_revision"]
          and name  == EXPECTED_DEFAULTS["product_name"]):
        print(f"[!!!] Conpot honeypot detected (fallback all-others match) → "
              f"vendor={vendor}, product_code={pcode}, "
              f"product_revision={prev}, product_name={name!r}")
    else:
        print(f"[i] Device non Conpot; valori osservati: "
              f"vendor={vendor}, devtype={devtype}, pcode={pcode}, "
              f"prev={prev}, serial={serial}, name={name!r}")
    # ----------------------------------------------

    ur = unregister_session(sock, session)
    print("[+] UnregisterSession response:")
    ur.show()

    # Reregistrazione per ulteriori comandi
    session = register_session(sock)

    # 4) Get_Attribute_Single su Identity Object (class=1,inst=1,attr=1..6)
    for a in range(1, 7):
        resp = get_attr_single(sock, session, cls=1, inst=1, attr=a)
        print(f"[>] Attr {a=} →")
        resp.show()

    # 5) Read tag Assembly (class=4, inst=1, attr=3)
    resp = get_attr_single(sock, session, cls=4, inst=1, attr=3)
    print("[>] Assembly data (class=4,inst=1,attr=3):")
    resp.show()

    # 6) Prova a scrivere il valore 0 su quel tag
    resp = set_attr_single(sock, session, cls=4, inst=1, attr=3, value=0)
    print("[>] Set_Attribute_Single (value=0) →")
    resp.show()

    # 7) Chiudi sessione
    ur2 = unregister_session(sock, session)
    print("[+] Session chiusa:")
    ur2.show()

    sock.close()

if __name__ == "__main__":
    main()
