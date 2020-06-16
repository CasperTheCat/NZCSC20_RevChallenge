# Hello, this is the solution for the NZCSC20 reversing challenge

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import struct
import requests

# The Key needs to be reversed
# The solution has this key in secret.key
key = ""
with open("secret.key", "rb") as f:
    key = f.read()

# The request for a flag is uint32_t(0)
# AEAD is used, so flipping a cyphertext bit won't work

# Context
aesgcmctx = AESGCM(key)

# Payload and IV
payload = struct.pack("I", 0)
iv = os.urandom(16)

# Encrypt and append
cyphertext = iv + aesgcmctx.encrypt(iv, payload, None)

# Get the flag
cryptflag = requests.post("http://127.0.0.1:8080/c2", data=cyphertext).content

# Decrypt it!
cfiv = cryptflag[:16]
cfdata = cryptflag[16:]
print("Got: {}".format(aesgcmctx.decrypt(cfiv, cfdata, None).decode()))


