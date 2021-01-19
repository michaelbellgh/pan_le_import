#import.py - Traefik letsencrypt certificate to Palo Alto Networks Firewall certificate
#Imports certificate of chosen common name from Traefik 2.2+ acme.json (lets encrypt) and imports it into the Palo Alto firewall
# NOTE: Requires cryptography 3+ module (for PFX functionality)
#Author - Michael Bell
import xml.etree.ElementTree as ET
import requests, json, base64, random, string, argparse
from cryptography import x509
import cryptography

from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12

import credentials

def get_acme_json(acme_json_file: string):
    f = open(acme_json_file, 'r')
    contents = f.read()
    f.close()
    return contents


def get_certificates(acme_json_contents):
    j = json.loads(acme_json_contents)

    certs_out = []

    #Iterate through the acme.json JSON structure and adds keys + certs to a dictionary
    for cert in j['letsencrypt']['Certificates']:
        main_domain = cert['domain']['main']
        certificate_b64 = cert['certificate']
        dictobj = {}
        dictobj['domain'] = main_domain
        dictobj['certificate'] = base64.b64decode(certificate_b64)
        dictobj['private_key'] = base64.b64decode(cert['key'])
        certs_out.append(dictobj)
    return certs_out

#Iterates through the certificate byte data, checks the common name
#Then returns if it matches common_name
def select_certificate(le_dict_list, common_name):
    for le_dict in le_dict_list:
        pem_bytes = le_dict['certificate']
        cert = x509.load_pem_x509_certificate(pem_bytes)
        cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        for common_name_obj in cns:
            if common_name_obj.value == common_name:
                return le_dict

#nice clean generator taken from https://pynative.com/python-generate-random-string/
def get_random_alphanumeric_string(length: int):
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return result_str

def generate_api_key(hostname: string, username: string, password: string, disable_ssl_validation: bool):
    xmlapi_key = requests.get("https://" + hostname + "/api/?type=keygen&user=" + 
                              username + "&password=" + password,verify=not disable_ssl_validation)
    xmlapi_key = ET.fromstring(xmlapi_key.text).find(".//key").text
    return xmlapi_key

def check_panos_errors(response):
    if isinstance(root_node, str):
        root_node = ET.fromstring(root_node)
    if root_node.attrib['status'] == 'success':
        if 'code' not in root_node.attrib:
            return True
        if root_node.attrib['code'] in ('19', '20'):
            return True
        elif root_node.attrib['code'] in ('7'):
            print("[WARN] Response returned success, but object not present")
            return True
        else:
            print("[WARN] Response returned success, but non standard response code: " + root_node.attrib['code'])
            return True
    elif 'code' in root_node.attrib:
       print("[ERROR] Response returned error code: " + root_node.attrib['code'] + "\n" + str(root_node.text))
       return False
    elif 'code' not in root_node.attrib:
        print("[ERROR] Response returned error")
        return False

#Creates a pkcs12 (.pfx) object/file and uploads to the Palo Alto firewall. Uses credentials.py for API key generation, firewall selection
def upload_certificate_to_paloalto(private_key: bytes, certificate: bytes, name: str, validate_ssl_certificate: bool):
    #Generates an auth key for subsequent requests
    if not hasattr(credentials, "username"):
        raise Exception("No username specified in credentials.py")
    if not hasattr(credentials, "password"):
        raise Exception("No password specified in credentials.py")
    xmlapi_key = requests.get("https://" + credentials.hostname + "/api/?type=keygen&user=" + 
                              credentials.username + "&password=" + credentials.password,verify=require_secure_cert)
    xmlapi_key = ET.fromstring(xmlapi_key.text).find(".//key").text

    rsa_key = load_pem_private_key(private_key, None)
    cert = x509.load_pem_x509_certificate(certificate)

    password = get_random_alphanumeric_string(18)

    #PANOS does not support periods in cert friendly name
    cert_friendly_name = name.replace(".", "-")

    pfx_bytes = pkcs12.serialize_key_and_certificates(name.encode(), rsa_key, cert, None, cryptography.hazmat.primitives.serialization.BestAvailableEncryption(password.encode()))

    #Uses PANOS XMLAPI to import PFX data.
    import_url = "https://" + credentials.hostname + "/api/?type=import&category=keypair&certificate-name=" + cert_friendly_name + "&format=pkcs12&passphrase=" + password
    response = requests.post(import_url + "&key=" + xmlapi_key, files={'file' : pfx_bytes},verify=disable_ssl_validation)
    print(response.text)

def commit_to_panos(hostname: string, api_key: string, validate_ssl_certificate: bool):
    commit_url = "https://" + hostname + "/api/?type=commit&cmd=<commit></commit>&key=" + api_key
    response = requests.get(commit_url, verify=validate_ssl_certificate)
    return check_panos_errors(response.text)

def get_config_option(args, key_name, default=None):
    arg = getattr(args, key_name)
    if arg is not None:
        return arg
    elif hasattr(credentials, key_name):
        return getattr(credentials, key_name)
    else:
        return default

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    parser.add_argument("--username", help="Define username to use to generate API key if not in credentials.py. Ignored if --apikey specified")
    parser.add_argument("--password", help="Define password to use to generate API key if not in credentials.py. Ignored if --apikey specified")
    parser.add_argument("--apikey", help="API Key to use when uploading certificate to PANOS device")
    parser.add_argument("--hostname", help="Hostname of PANOS device to use if not specified in credentials.py")
    parser.add_argument("--acme_json", help="Location of acme.json certificate storage file if not specified in credentials.py")
    parser.add_argument("--cert_common_name", help="Common name (CN) of certificate to extract from acme.json if not specified in credentials.py. Uses first found match")
    parser.add_argument("--cert_output_location", help="Location to store certificate and key if not specified in credentials.py. Ignored if --keep_files not specified")
    parser.add_argument("--keep_files", help="Delete .crt and.key files after upload. Defaults to False", default=False, action="store_true")
    parser.add_argument("--disable_ssl_validation", default=False, action="store_true", help="Disables SSL Certificate validation for connecting to PANOS device if set to True. Defaults to False")
    parser.add_argument("--commit", action="store_true", default=False, help="Commit the firewall/Panorama configuration if set. Note: Does not support Panorama pushing of configuration")

    args = parser.parse_known_args()

    acme_json = ""
    hostname = ""
    cert_common_name = ""
    cert_output_location = ""
    api_key = ""
    disable_ssl_validation = False

    if args.acme_json is not None:
        acme_json = args.acme_json
    elif hasattr(credentials, "acme_json"):
        acme_json = credentials.acme_json
    else:
        raise Exception("No ACME JSON location specified. Use --acme_json or specify acme_json=location/to/traefik_acme.json in credentials.py")

    cert_common_name = get_config_option(args, "cert_common_name")
    if cert_common_name is None:
        raise Exception("No certificate common name specified. Use --cert_common_name or specify cert_common_name=my_common_name in credentials.py")

    disable_ssl_validation = get_config_option(args, "disable_ssl_validation")
    if disable_ssl_validation is None:
        disable_ssl_validation = False

    keep_files = get_config_option(args, "keep_files")
    if keep_files is None:
        keep_files = False

    hostname = get_config_option(args, "hostname")
    if hostname is None:
        raise Exception("No hostname specified. Use --hostname or specify hostname=mypanoshostname in credentials.py")

    api_key = get_config_option(args, "apikey")
    if api_key is None and hasattr(credentials, "username") and hasattr(credentials, "password"):
        api_key = generate_api_key(credentials.username, credentials.password)
    else:
        raise Exception("No API key or username+password specified. Use --apikey XXX OR --username myusername --password=mypassword OR \n" + \
            "Specify apikey=XXX or username=myusername password=mypassword in credentials.py")

    cert_output_location = get_config_option(args, "cert_output_location")
    commit = get_config_option(args, "commit")

    json_contents = get_acme_json(acme_json)
    certs = get_certificates(json_contents)

    cert_dct = select_certificate(certs, cert_common_name)

    if cert_dct is None:
        print("[ERROR] No certificate matching common name " + cert_common_name + " was found in acme.json. Aborting")
        sys.exit(1)
    
    if cert_output_location is not None and keep_files:
        open(cert_output_location + cert_common_name + ".crt", "wb").write(cert_dct['certificate'])
        open(cert_output_location + +cert_common_name + ".key", "wb").write(cert_dct['private_key'])
    
    upload_certificate_to_paloalto(cert_dct['private_key'], cert_dct['certificate'],
                                   cert_common_name, not disable_ssl_validation)
    if commit:
        if commit_to_panos(hostname, api_key, not disable_ssl_validation):
            print("[INFO] Commit request sent succesfully")
    

main()
