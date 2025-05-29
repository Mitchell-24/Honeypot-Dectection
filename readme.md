# Honeypot Detection

Program to detect if a host is a honeypot by checking for known honeypot signatures.

## Requirements

- Python 3.13
- nmap
- ipmitool

### Python dependencies

Make sure these are installed.

- c104 2.2.1
- certifu 2025.4.26
- charset-normalizer 3.4.2
- idna 3.10
- requests 2.32.3
- urllib3 2.4.0
- scapy 2.6.1
- crcmod 1.7

## Usage

Run `main.py [Host-Address]` . The host address is `localhost` if you run the honeypot locally. Add the `-s` flag to also do a full port scan.

You can add a new signature by creating a new python file with the name `honeypot_protocol`. Make sure the file has a function `test(address)` which returns True if the signature can be elicited from the host, and False otherwise. Make sure it does not print anything and does not get stuck.

### IPInfo

The program uses the IPInfo.io API to gather additional information about target hosts, including:

- Hostname (if available)
- City and Region
- Country
- Organization/ASN
- Timezone

To get the most out of IPInfo and avoid rate limiting:

1. Sign up for an API key at [ipinfo.io](https://ipinfo.io)
2. Set the environment variable before running:
   
   ```bash
   export IPINFO_API_KEY='your_api_key_here'
   ```

If no API key is provided, the program will still work but requests may be throttled. 
