# twilio-pkcv-blog

Public Key Client Validation is implemented using the following general steps:

1. Create new API Key/ Secret Pair

2. Generate an RSA Key Pair

3. Submit the RSA Public Key to Twilio

4. Canonicalize and Hash the Request

5. Generate JWT

6. Attach JWT to the request header

Steps 3 (api_rsa_keys.py) only needs to be done once per HTTP client. You need a MAIN API Key Secret for this - https://www.twilio.com/docs/iam/api-keys#types-of-api-keys

Steps 4-6 (homemade_pkcv_requests.py) use this information to make requests to Twilio's API.
