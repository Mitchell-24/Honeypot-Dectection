# Honeypot Detection

Program to detect if a host is a honeypot by checking for known honeypot signatures.

## Hosts

### Suspected honeypots:

*running s7*

plant_id="Mouser Factory" (found by censys):

- 167.99.214.253
- 140.82.56.253 (140.82.56.253.vultrusercontent.com) 
- 93.95.250.34 (A LOT OF OPEN PORTS)

*running s7 AND modbus*

- 144.178.194.182 (144-178-194-182.static.ef-service.nl) 

*running IEC104*

- 104.248.194.231 (A LOT OF OPEN PORTS)

*running IEC104 AND ATG*

- 209.250.249.170 (209.250.249.170.vultrusercontent.com) 
- 45.58.159.21 (customer.sharktech.net) 
- 94.131.107.115 (vm3903957.stark-industries.solutions)
- 141.144.201.128

*running Bacnet*
- 185.177.125.34 

### Suspected real hosts:

*running S7*

- 92.64.233.255 (92-64-233-255.biz.kpn.net) 
- 46.226.237.96 (46-226-237-96.bb.deanone.nl) 

*running IPMI*

- 194.88.106.207 (194-88-106-207.hosted-by-worldstream.net)
- 23.157.176.252
- 78.41.206.17

*running IEC104*

- 40.68.89.30
- 91.199.166.15

*running Modbus*

- 5.199.159.181 (ftth-005-199-159-181.solcon.nl) 
- 89.200.92.97 (89-200-92-97.mobile.kpn.net) 
- 149.143.15.30 (149-143-15-30-static.ngblunetworks.nl) 
- 113.212.72.100 (static.ritesim.com) 

*running ATG*
- 68.34.86.183
- 98.0.169.30 (syn-098-000-169-030.biz.spectrum.com)
- 218.60.50.160

*running Bacnet*
- 84.31.197.242 
- 77.62.188.115
- 77.62.162.78

## Requirements

- Python 3
- ipmitool

### Python dependencies

Make sure these are installed. If you add code that requires new dependencies, please add them to this list. 

- python3-c104

## Usage

Run `main.py [Host-Address]` . The host address is `localhost` if you run the honeypot locally.

You can add a new signature by creating a new python file with the name `honeypot_protocol`. Make sure the file has a function `test(address)` which returns True if the signature can be elicited from the host, and False otherwise. Make sure it does not print anything and does not get stuck.
