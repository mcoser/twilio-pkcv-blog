import base64
import hashlib
import os
import time
import urllib.parse

import jwt  # PyJWT library - https://pyjwt.readthedocs.io/en/stable/
import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
API_KEY = os.environ.get("TWILIO_API_KEY")
API_SECRET = os.environ.get("TWILIO_API_SECRET")
CREDENTIAL_SID = os.environ.get("TWILIO_CREDENTIAL_SID")
PRIVATE_PEM_FILE = os.environ.get("PRIVATE_PEM_FILE")

PASSPHRASE = os.environ.get("PRIVATE_KEY_ENCRYPTION_PASSPHRASE").encode()

# Load the private key
with open(PRIVATE_PEM_FILE, "rb") as key_file:
    private_key_pem = load_pem_private_key(
        key_file.read(),
        password=PASSPHRASE,  # Adjust the password as needed
    )

def create_basic_auth_str(key, secret):
    data = f"{key}:{secret}"
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

def canonicalize_http_method(method):
    return method.strip().upper()

def canonicalize_resource_path(path):
    normalized_path = urllib.parse.urlparse(path).path
    if not normalized_path:
        return '/'
    return urllib.parse.quote(normalized_path, safe='/-_.!=')

def canonicalize_query_string(query_string):
    query_params = urllib.parse.parse_qsl(query_string, keep_blank_values=True)
    sorted_params = sorted((urllib.parse.quote(k, safe='/-_.!='),
                            urllib.parse.quote(v, safe='/-_.!='))
                           for k, v in query_params)
    return '&'.join(f"{k}={v}" for k, v in sorted_params)

def canonicalize_headers(headers):
    canonical = []
    print(headers)
    for key, value in headers.items():
        clean_key = key.lower().strip()
        clean_value = ' '.join(value.strip().split())
        canonical.append(f"{clean_key}:{clean_value}")
    canonical.sort()
    print('\n'.join(canonical) + '\n')
    return '\n'.join(canonical) + '\n'

def canonicalize_signed_headers(headers):
    signed_headers = [key.lower() for key in headers]
    signed_headers.sort()
    return ';'.join(signed_headers)

def hash_request_body(body):
    if body:
        return hashlib.sha256(body.encode('utf-8')).hexdigest()
    return ''

def create_canonical_request(http_method, path, query_string, headers, body):
    print(query_string)
    return '\n'.join([
        canonicalize_http_method(http_method),
        canonicalize_resource_path(path),
        canonicalize_query_string(query_string),
        canonicalize_headers(headers),
        canonicalize_signed_headers(headers),
        hash_request_body(body)
    ])

def create_jwt(canonical_request, api_key, account_sid, credential_sid, private_key):
    request_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    jwt_headers = {
        "cty": "twilio-pkrv;v=1", # ContentType = Twilio Public Key Request Validation - Version 1
        "typ": "JWT", # Media Type = JSON Web Token, other values rejected
        "alg": "RS256", # One of RS256 or PS256. These are the only algorithms supported at the moment. RS256 = RSASSA-PKCS-v1_5 using SHA-256 hash algorithm. PS256 = RSASSA-PSS using SHA-SHA 256 hash algorithm.
        "kid": credential_sid # Key ID = Identifier of the public key credential associated with the private key used to sign the JWT
    }

    jwt_payload = {
        "hrh": "authorization;host", # A ';' (semicolon) delimited list of lowercase headers to include in the request hash calculation. At a minimum, you must include 'Host' and 'Authorization'
        "rqh": request_hash, # Hash of the Canonical Request
        "iss": api_key, # Issuer = APIKey Sid used to match against request credentials
        "exp": int(time.time()) + 300, # Token Expiry Time: token received after exp +- clock skew will be rejected. Max exp - nbf is 300 seconds
        "nbf": int(time.time()), # Not Before Time: (Default: 'now')
        "sub": account_sid # Subject = AccountSid
    }

    jwt_token = jwt.encode(jwt_payload, private_key, algorithm="RS256", headers=jwt_headers)
    return jwt_token

# Example usage
http_method = 'GET'
query_string = 'Status=no-answer'
path = f'/2010-04-01/Accounts/{ACCOUNT_SID}/Calls.json?{query_string}'
headers = {
    'Host': 'api.twilio.com',
    'Authorization': f'Basic {create_basic_auth_str(API_KEY, API_SECRET)}'
}
body = ''

def send_request(http_method, path, headers, body):
    canonical_request = create_canonical_request(http_method, path, query_string, headers, body)
    print(canonical_request)
    jwt_token = create_jwt(canonical_request, API_KEY, ACCOUNT_SID, CREDENTIAL_SID, private_key_pem)
    print(jwt_token)
    headers['Twilio-Client-Validation'] = jwt_token
    url = f"https://api.twilio.com{path}"
    response = requests.request(http_method, url, headers=headers, data=body)
    return response


response = send_request(http_method, path, headers, body)
print("Response Status Code:", response.status_code)
print("Response Body:", response.text)
