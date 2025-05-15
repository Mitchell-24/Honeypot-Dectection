from subprocess import run, CalledProcessError


def test(address):
    cmd_info = f"ipmitool -I lanplus -H {address} -p 6230 -C3 -U Administrator -P Password mc info"
    cmd_reset_warm = f"ipmitool -I lanplus -H {address} -p 6230 -C3 -U Administrator -P Password mc reset warm"
    cmd_selftest = f"ipmitool -I lanplus -H {address} -p 6230 -C3 -U Administrator -P Password mc selftest"
    cmd_userlist = f"ipmitool -I lanplus -H {address} -p 6230 -C3 -U Administrator -P Password user list"
    
    info = run(cmd_info, shell=True, capture_output=True).stdout
    user_list = run(cmd_userlist, shell=True, capture_output=True).stdout

    print(info.decode())
    print(user_list.decode())
    
    ### Command with exploitable bug? If one resets to 
    ###     'cold', one gets the response: 'Sent cold reset command to MC'
    ###     'warm', one gets the response: 'MC reset command failed: Invalid command'
    try:

        run(cmd_reset_warm, shell=True, capture_output=True, check=True)

    except CalledProcessError as e:
        err_msg = e.stderr.decode()
        if err_msg == "MC reset command failed: Invalid command\n":
            return True


    ### Example where conpot just returns: 'I have no fucking clue'
    try:

        run(cmd_selftest, shell=True, capture_output=True, check=True)

    except CalledProcessError as e:
        err_msg = e.stderr.decode()
        if err_msg == "Bad response: (Invalid command)\n":
            return True

    #run(cmd_userlist, shell=True, capture_output=True)
    
    return False

test("localhost")