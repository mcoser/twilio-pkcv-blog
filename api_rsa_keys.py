import base64
import http.client
import json
import logging
import os
from datetime import datetime
from urllib.parse import urlencode

import requests
from requests.auth import HTTPBasicAuth

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID") # PKCV Sub Acct
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY") # PKCV Sub Acct Main Key
ADMIN_API_SECRET = os.environ.get("ADMIN_API_SECRET")# PKCV Sub Acct Main Key Secret
PASSPHRASE = os.environ.get("PRIVATE_KEY_ENCRYPTION_PASSPHRASE").encode() # Used to encrypt the RSA private key
now_date = datetime.now().strftime("%m-%d-%Y_%I-%M-%S") # For a unique str to add to the API Key Friendly Name

# Configure logging with timestamp format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def base64_basicauth(key, secret):
    auth_str = f"{key}:{secret}"
    encoded_bytes = base64.b64encode(auth_str.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

def generate_and_submit(passphrase):

    ##########
    # Step 1 - Create a new API Key/ Secret Pair w/ Twilio and python requests
    # https://www.twilio.com/docs/iam/api-keys/key-resource-v1
    ##########
    api_key_url = f"https://iam.twilio.com/v1/Keys"
    api_key_data = {
        "FriendlyName": f"pkcv-standard-api-key_{now_date}",
        "AccountSid": ACCOUNT_SID
    }
    http_auth = HTTPBasicAuth(ADMIN_API_KEY, ADMIN_API_SECRET)
    try:
        api_key_response = requests.post(api_key_url, data=api_key_data, auth=http_auth).json()
        new_api_key_sid = api_key_response['sid']
        new_api_key_secret = api_key_response['secret']
        logging.info("API Key/ Secret Pair successfully created...")
    except Exception as e:
        logging.error(f"{e}")
       
    ##########
    # Step 2 - Generate RSA Key Pair with cryptography package
    # https://pypi.org/project/cryptography/
    ##########

    # A private key is generated with math - https://archive.org/details/arxiv-cs9903001/mode/2up
    private_key = rsa.generate_private_key(
        public_exponent=65537, # used in cryptographic algorithm to derive the private key
        key_size=2048, # size of the key in bits - 2048 is secure
        backend=default_backend() # https://cryptography.io/en/3.0/hazmat/backends/#getting-a-backend
    )

    # The public key is derived from the private key
    public_key = private_key.public_key() 

    # Load the private pem file as a bytestring and save it to the current working directory
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
    )
    with open(f"{new_api_key_sid}_private.pem", "wb") as private_file:
        private_file.write(private_pem)
        logging.info("RSA Private Key successfully generated and saved...")

    # Load the public key as a bsytrstring, and save it as well
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f"{new_api_key_sid}_public.pem", "wb") as public_file:
        public_file.write(public_pem)
        logging.info("RSA Public Key successfully generated and saved...")


    ############
    # Step 3 - Submit RSA Public Key to Twilio
    # For fun (or necessity), the standard http client library can used instead of the external 'requests' package
    # https://github.com/python/cpython/blob/3.13/Lib/http/client.py
    ############
    conn = http.client.HTTPSConnection("accounts.twilio.com")
    api_key_data = {
        "FriendlyName": f"{new_api_key_sid}-publickey",
        "PublicKey": public_pem
    }
    encoded_data = urlencode(api_key_data)
    headers = {
        'Authorization': f'Basic {base64_basicauth(ADMIN_API_KEY, ADMIN_API_SECRET)}', # Need to use a Main Key to manage keys
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    api_key_url_path = f"/v1/Credentials/PublicKeys"
    conn.request("POST", api_key_url_path, encoded_data, headers)
    response = conn.getresponse()
    response_data = response.read().decode()
    if response.status != 201:
        logging.error(f"Error POSTing to {api_key_url_path}")
    else:
        response_json = json.loads(response_data)
        new_credential_sid = response_json.get('sid')
        logging.info("Public Key submitted to Twilio Successfully!")
    conn.close()

    # Done!
    
    print("\n A New PKCV client has been successfully generated \n")
    print("Copy the following into the bottom of venv/bin/activate, and reactive the virtual environment: \n")
    print(f"export TWILIO_API_KEY={new_api_key_sid}")
    print(f"export TWILIO_API_SECRET={new_api_key_secret}")
    print(f"export TWILIO_CREDENTIAL_SID={new_credential_sid}")
    print(f"export PRIVATE_PEM_FILE={new_api_key_sid}_private.pem")
    print(f"export PUBLIC_PEM_FILE={new_api_key_sid}_public.pem")
    return

generate_and_submit(PASSPHRASE)
