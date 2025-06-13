import functools
import time
import c104
from conpot_iec104_helper import *
import random

IMPL_CMD_TYPE = c104.Type.C_SC_NA_1
NOT_IMPL_CMD_TYPE = c104.Type.C_SC_TA_1

CONPOT_INRO_TYPES = [c104.Type.M_SP_NA_1, c104.Type.M_DP_NA_1, c104.Type.M_ST_NA_1, 
                     c104.Type.M_BO_NA_1, c104.Type.M_ME_NA_1, c104.Type.M_ME_NB_1, 
                     c104.Type.M_ME_NC_1]

class C104Conn:

    def __init__(self, ct: c104.Connection):
        self.has_config_sigs = False
        self.has_impl_sigs = False
        self.ct = ct

    def fetch_non_existing_endpoint(self):
        epts_ads = []
        for st in self.ct.stations:
            for pt in st.points:
                epts_ads.append(pt.io_address)
        
        r = epts_ads[0]
        while r in epts_ads:
            r = random.randint(0, 2**24-1)

        return r

    def check_config_sigs(self):
        ct_st_count = len(self.ct.stations)

        if not ct_st_count == 1:
            return False

        st = self.ct.stations[0]
        st_pt_count = len(st.points)

        if not st_pt_count == 59:
            return False

        if not st.common_address == 7720:
            return False
        
        return True

    def check_impl_sigs(self):
        for st in self.ct.stations:

            # command requests at random endpoints
            ia1 = self.fetch_non_existing_endpoint()
            ia2 = self.fetch_non_existing_endpoint()

            while ia1 == ia2:
                ia2 = self.fetch_non_existing_endpoint()

            cmd_implemented = st.add_point(ia1, IMPL_CMD_TYPE)
            cmd_not_implemented = st.add_point(ia2, NOT_IMPL_CMD_TYPE)

            cmd_implemented.transmit(c104.Cot.ACTIVATION)
            time.sleep(.2)
            cmd_not_implemented.transmit(c104.Cot.ACTIVATION)
            time.sleep(.2)


    def parse_response_raw(self, connection: c104.Connection, data: bytes) -> None:

        frame = c104.explain_bytes_dict(apdu=data)

        if frame['format'] == 'I':
            
            # 1: conpot tends to set OA = 0 in response
            if frame['originatorAddress'] == 0:
                
                # 2: if we get response for the implemented command request at the endpoint
                # with IA = 2**24-1, conpot detects it and sets the 'IA not found' flag
                # NOTE: in theory real hosts could also act like this, but in practice I didnt find this with OA = 0
                if frame['type'] == IMPL_CMD_TYPE and frame['cot'] == c104.Cot.UNKNOWN_IOA:
                    self.has_impl_sigs = True

                # 3: if we get response for not implemented command,
                # this is not response from conpot (conpot does not reply in this case)
                if frame['type'] == NOT_IMPL_CMD_TYPE:
                    self.has_impl_sigs = False

                # 4: conpot is only capable of responding with certain types of endpoint
                if frame['cot'] == c104.Cot.INTERROGATED_BY_STATION and frame['type'] not in CONPOT_INRO_TYPES:
                    self.has_impl_sigs = False

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
    cl_connection_1 = my_client.add_connection(ip=address, port=2404, init=c104.Init.NONE)
    ct = C104Conn(cl_connection_1)
    #cl_connection_1.on_unexpected_message(callable=con_on_unexpected_message)

    ### Register callbacks to print connection info
    #register_callbacks(my_client, cl_connection_1)

    cl_connection_1.on_receive_raw(ct.parse_response_raw)

    my_client.start()

    counter = 0
    while not cl_connection_1.is_connected and counter < 5:
        #print("CL] Waiting for connection to {0}:{1}".format(cl_connection_1.ip, cl_connection_1.port))
        time.sleep(1)
        counter += 1

    cl_connection_1.interrogation(0xFFFF)
    
    ct.check_impl_sigs(cl_connection_1)
    has_config_sigs = ct.check_config_sigs(cl_connection_1)

    ### Dump all point data stored in the ICS system that hosts the server
    #cl_dump(my_client, cl_connection_1)

    my_client.stop()

    #print(has_impl_sigs)

    return has_config_sigs, ct.has_impl_sigs

if __name__ == "__main__":
    test("localhost")