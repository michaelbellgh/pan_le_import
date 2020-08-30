#import.py - Traefik letsencrypt certificate to Palo Alto Networks Firewall certificate
#Imports certificate of chosen common name from Traefik 2.2+ acme.json (lets encrypt) and imports it into the Palo Alto firewall
# NOTE: Requires cryptography 3+ module (for PFX functionality)
#Author - Michael Bell
import xml.etree.ElementTree as ET
import requests, json, base64, random, string
from cryptography import x509
import cryptography

from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12



import credentials

ACME_JSON_LOCATION = credentials.traefik_acme_location

def get_acme_json():
    f = open(ACME_JSON_LOCATION, 'r')
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

#Iterates through the certificate byte data, checks the common name, and returns if it matches common_name
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

#Creates a pkcs12 (.pfx) object/file and uploads to the Palo Alto firewall. Uses credentials.py for API key generation, firewall selection
def upload_certificate_to_paloalto(private_key: bytes, certificate: bytes, name: str):
    #Generates an auth key for subsequent requests
    xmlapi_key = requests.get("https://" + credentials.hostname + "/api/?type=keygen&user=" + 
                              credentials.username + "&password=" + credentials.password)
    xmlapi_key = ET.fromstring(xmlapi_key.text).find(".//key").text

    rsa_key = load_pem_private_key(private_key, None)
    cert = x509.load_pem_x509_certificate(certificate)

    password = get_random_alphanumeric_string(18)

    #PANOS does not support periods in cert friendly name
    cert_friendly_name = name.replace(".", "-")

    pfx_bytes = pkcs12.serialize_key_and_certificates(name.encode(), rsa_key, cert, None, cryptography.hazmat.primitives.serialization.BestAvailableEncryption(password.encode()))

    #Uses PANOS XMLAPI to import PFX data.
    import_url = "https://" + credentials.hostname + "/api/?type=import&category=keypair&certificate-name=" + cert_friendly_name + "&format=pkcs12&passphrase=" + password
    response = requests.post(import_url + "&key=" + xmlapi_key, files={'file' : pfx_bytes})
    print(response.text)

def main():
    json_contents = get_acme_json()
    certs = get_certificates(json_contents)
    cert_dct = select_certificate(certs, credentials.cert_common_name)
    if cert_dct is None:
        print("[ERROR] No certificate matching common name " + credentials.cert_common_name + " was found in acme.json. Aborting")
        return
    upload_certificate_to_paloalto(cert_dct['private_key'], cert_dct['certificate'],
                                   credentials.cert_common_name)

main()