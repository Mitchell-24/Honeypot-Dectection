# Honeypot Detection

Program to detect if a host is a honeypot by checking for known honeypot signatures.

## Requirements

- Python 3

### Dependencies

Make sure these are installed. If you add code that requires new dependencies, please add them to this list. 

- c104 



## Usage

Run `main.py`. The script will prompt you for the address of the target host. This is `localhost` if you run the honeypot locally.

You can add a new signature by creating a new python file with the name `honeypot_protocol`. Make sure the file has a function `test(address)` which returns True if the signature can be elicited from the host, and False otherwise. Make sure it does not print anything and does not get stuck.


## Hosts
# SUSPECTED HONEYPOTS:

*running s7*

plant_id="Mouser Factory" (found by censys):
167.99.214.253
140.82.56.253 (140.82.56.253.vultrusercontent.com) 
93.95.250.34 (A LOT OF OPEN PORTS)

*running s7 AND modbus*

144.178.194.182 (144-178-194-182.static.ef-service.nl) 


# SUSPECTED REAL HOSTS:

*running S7*

92.64.233.255 (92-64-233-255.biz.kpn.net) 
46.226.237.96 (46-226-237-96.bb.deanone.nl) 

*running IPMI*

194.88.106.207 (194-88-106-207.hosted-by-worldstream.net)
23.157.176.252
78.41.206.17
