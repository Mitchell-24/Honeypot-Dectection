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
