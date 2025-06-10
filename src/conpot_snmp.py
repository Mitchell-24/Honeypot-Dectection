from pysnmp.hlapi import *

PORT = 16100
TIMEOUT = 30
COMMUNITY = 'public'

SIGNATURE_PATTERNS = [
    "Siemens, SIMATIC, S7-200",
    "Siemens AG",
    "CP 443-1 EX40",
    "Venus",
    "72",
    "0",
    "1.3.6.1.4.1.20408"
]

def test(address):
    """
    Tests whether the given host behaves like a Conpot honeypot.
    :param address: IP or hostname
    :return: True if signature found, False otherwise
    """
    target = UdpTransportTarget((address, PORT))
    count = 0
    for (errInd, errStat, _, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.1')), 
        lexicographicMode=False
    ):
        if errInd or errStat:
            break
        for varBind in varBinds:
            oid, val = varBind
            text = str(val)
            for sig in SIGNATURE_PATTERNS:
                if sig in text:
                    count += 1
                    break
    return count > 0
    

