from flask import Flask, render_template, request, make_response
import sys
import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import struct
import random
import os
import waitress

# OBFS
CONST_FLASK_OBFS=True
CONST_FAKE_RETCODE = [404, 301, 403]

## Flask Header Overrides
class lyqFlask(Flask):
    def process_response(self, response):
        tresp = super().process_response(response)

        tresp.headers['Server'] = "Apache/2.4.1 (Unix)"
        tresp.headers['Cache-Control'] = "max-age=0, nocache, nostore"
        tresp.headers['flag'] = "UnitedKingdom"
        return(tresp)

def ObfuscateRetCode(NominalCode: int):
    if not app.debug and CONST_FLASK_OBFS:
        return random.choice(CONST_FAKE_RETCODE)

    return NominalCode

app = lyqFlask(__name__)

key = []
# Read the key
with open("secret.key", "rb") as f:
    print("GotKey")
    key = f.read()#struct.unpack("IIII", f.read())

#print("{:2x}".format(key[0]))
#for 
#key = key.to_bytes(16, byteorder='little')
#print(key)

cryptoctx = AESGCM(key)
nFinishers = 0

@app.route("/")
def Root():
    return render_template('test.html'), ObfuscateRetCode(200)

@app.route("/c2", methods=['GET'])
def meme():
    return render_template('story.html', post={"title": "FLAG is HERE", "content": "EuropeanUnion"}), 200

@app.route("/c2", methods=['POST'])
def gmpHandler():
    global nFinishers
    pucket = request.get_data()
    data = pucket[16:]
    iv = pucket[:16]

    try:
        decryptData = cryptoctx.decrypt(iv, data, None)
        header = struct.unpack("I", decryptData[:4])[0]


        # Switchmode_
        if(header == 0):
            print("SOMEBODY GOT THAT SWEET SWEET FLAG")
            plaintext = """Congratulations on completing the NZCSC Reversing Challenge!!!
    So far, the flag has been dispenced {} times :)
    flag:airbusBeluga""".format(nFinishers).encode()
            
            nFinishers += 1
            
            print(len(plaintext))

            mouse = os.urandom(16)

            cyphertext = cryptoctx.encrypt(mouse, plaintext, None)

            #header = struct.pack("I", len(mouse+cyphertext))

            retResp = make_response(mouse + cyphertext)
            return retResp
        
        elif(header == 1):
            #print("COMMAND: GETRAND")
            randRet = os.urandom(4) # Random uint32_t for reting
            #randRet = b'\0' * 16;

            mouse = os.urandom(16)

            cyphertext = cryptoctx.encrypt(mouse, randRet, None)

            #header = struct.pack("I", len(mouse+cyphertext))

            retResp = make_response(mouse + cyphertext)
            return retResp

    except InvalidTag as identifier:
        return render_template('story.html', post={"title": "BadTag", "content": []}), 200

    return render_template('story.html', post={"title": "HI", "content": "hi"}), 200

if __name__ == "__main__":
    waitress.serve(app, listen="*:8080")
