import functools
import c104

##################################
# CONNECTION STATE HANDLER
##################################

def cl_ct_on_state_change(connection: c104.Connection, state: c104.ConnectionState) -> None:
    print("CL] Connection State Changed {0} | State {1}".format(connection.originator_address, state))



##################################
# NEW DATA HANDLER
##################################

def cl_pt_on_receive_point(point: c104.Point, previous_info: c104.Information, message: c104.IncomingMessage) -> c104.ResponseState:
    print("CL] {0} REPORT on IOA: {1}, message: {2}, previous: {3}, current: {4}".format(point.type, point.io_address, message, previous_info, point.info))
    # print("{0}".format(message.is_negative))
    # print("-->| POINT: 0x{0} | EXPLAIN: {1}".format(message.raw.hex(), c104.explain_bytes(apdu=message.raw)))
    return c104.ResponseState.SUCCESS



##################################
# NEW OBJECT HANDLER
##################################

def cl_on_new_station(client: c104.Client, connection: c104.Connection, common_address: int, custom_arg: str, y: str = "default value") -> None:
    print("CL] NEW STATION {0} | CLIENT OA {1}".format(common_address, client.originator_address))
    connection.add_station(common_address=common_address)


def cl_on_new_point(client: c104.Client, station: c104.Station, io_address: int, point_type: c104.Type) -> None:
    print("CL] NEW POINT: {1} with IOA {0} | CLIENT OA {2}".format(io_address, point_type, client.originator_address))
    point = station.add_point(io_address=io_address, type=point_type)
    point.on_receive(callable=cl_pt_on_receive_point)



##################################
# RAW MESSAGE HANDLER
##################################

def cl_ct_on_receive_raw(connection: c104.Connection, data: bytes) -> None:
    print("CL] <-in-- {1} [{0}] | CONN OA {2}".format(data.hex(), c104.explain_bytes_dict(apdu=data), connection.originator_address))


def cl_ct_on_send_raw(connection: c104.Connection, data: bytes) -> None:
    print("CL] -out-> {1} [{0}] | CONN OA {2}".format(data.hex(), c104.explain_bytes_dict(apdu=data), connection.originator_address))



##################################
# Dump points
##################################

def cl_dump(my_client, cl_connection_1):
    
    if cl_connection_1.is_connected:
        print("")
        cl_ct_count = len(my_client.connections)
        print("CL] |--+ CLIENT has {0} connections".format(cl_ct_count))
        for ct_iter in range(cl_ct_count):
            ct = my_client.connections[ct_iter]
            ct_st_count = len(ct.stations)
            print("       |--+ CONNECTION has {0} stations".format(ct_st_count))
            for st_iter in range(ct_st_count):
                st = ct.stations[st_iter]
                st_pt_count = len(st.points)

                print("          |--+ STATION {0} has {1} points".format(st.common_address, st_pt_count))
                print("             |      TYPE      |   IOA   |       VALUE        |        PROCESSED AT        |        RECORDED  AT        |      QUALITY      ")
                print("             |----------------|---------|--------------------|----------------------------|----------------------------|-------------------")
                for pt_iter in range(st_pt_count):
                    pt = st.points[pt_iter]
                    print("             | %s | %7s | %18s | %26s | %26s | %s" % (pt.type, pt.io_address, pt.value, pt.processed_at.isoformat(),
                                                                                 pt.recorded_at and pt.recorded_at.isoformat() or 'N. A.', pt.quality))
                    print("             |----------------|---------|--------------------|----------------------------|----------------------------|-------------------")


def register_callbacks(my_client, cl_connection_1):

    #cl_connection_1.on_state_change(callable=cl_ct_on_state_change)

    #my_client.on_new_station(callable=functools.partial(cl_on_new_station,
    #                                                    custom_arg="extra argument with default/bounded value passes signature check"))
    #my_client.on_new_point(callable=cl_on_new_point)

    #cl_connection_1.on_receive_raw(callable=cl_ct_on_receive_raw)
    cl_connection_1.on_send_raw(callable=cl_ct_on_send_raw)


def con_on_unexpected_message(connection: c104.Connection, message: c104.IncomingMessage, cause: c104.Umc) -> None:
    if cause == c104.Umc.MISMATCHED_TYPE_ID :
        station = connection.get_station(message.common_address)
        if station:
            point = station.get_point(message.io_address)
            if point:
                print("CL] <-in-- CONFLICT | SERVER CA {0} reports IOA {1} type as {2}, but is already registered as {3}".format(message.common_address, message.io_address, message.type, point.type))
                return
    print("CL] <-in-- REJECTED | {1} from SERVER CA {0}".format(message.common_address, cause))