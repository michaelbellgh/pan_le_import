# pan_le_import
## Traefik ACME certs to PANOS certificates
Small tool to read the Traefik 2.2+ acme.json file and import a chosen certificate into a Palo Alto Networks firewall certificate store using the XMLAPI.

## Requirements
pip module cryptography => 3.1
# Usage

Create a file named 'credentials.py' with the following information:
```
username = "Palo Alto username"
password = "Palo Alto password"
hostname = "Palo Alto firewall hostname or IP address"
traefik_acme_location = "/local/path/to/acme.json"
commit=True
keep_files=True
disable_ssl_validation=True
```
Run with python:

    python3 import.py

## Todo

 - Add robust error checking
 - Add support for Panorama pushing
