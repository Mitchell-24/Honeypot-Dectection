import functools
import time
import c104
from conpot_iec104_helper import *

def is_conpot(my_client):
    cl_ct_count = len(my_client.connections)

    if not cl_ct_count == 1:
        return False

    ct = my_client.connections[0]
    ct_st_count = len(ct.stations)

    if not ct_st_count == 1:
        return False

    st = ct.stations[0]
    st_pt_count = len(st.points)

    if not st_pt_count == 59:
        return False

    if not st.common_address == 7720:
        return False
    
    return True



def test(address):
    """
    Tests if the host has the Conpot IEC104 signature.
    :param address: The IP address of the host.
    :return: True if the signature is found, False otherwise.
    """
    ### Debug mode
    #c104.set_debug_mode(mode=c104.Debug.Client|c104.Debug.Connection)
    #print("CL] DEBUG MODE: {0}".format(c104.get_debug_mode()))

    my_client = c104.Client(tick_rate_ms=1000, command_timeout_ms=5000)
    my_client.originator_address = 123
    cl_connection_1 = my_client.add_connection(ip=address, port=2404, init=c104.Init.ALL)


    ### Register callbacks to print connection info
    #register_callbacks(my_client, cl_connection_1)

    my_client.start()

    counter = 0
    while not cl_connection_1.is_connected and counter < 2:
        #print("CL] Waiting for connection to {0}:{1}".format(cl_connection_1.ip, cl_connection_1.port))
        time.sleep(1)
        counter += 1

    conpot = is_conpot(my_client)

    ### Dump all point data stored in the ICS system that hosts the server
    #cl_dump(my_client, cl_connection_1)

    my_client.stop()

    return conpot