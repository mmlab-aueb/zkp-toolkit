'''
import base64
from ursa_bbs_signatures import BlsKeyPair

bls_key_pair = BlsKeyPair.generate_g2()
base64.b64encode(bls_key_pair.public_key)
base64.b64encode(bls_key_pair.secret_key)
'''

from signer import Signer
from prover import Prover
from verifier import Verifier
import base64
import json

bbs_public_key = 'gh9/xep0FZmatNY1oQgQDDR3TFi6ZgAnXlaRt60Lm4fu0iGJT1+4t69EpHvGG0mqAv1CPIor6G50MzzPzC1sMUGwurGGMnSiUVkFpM6Fs3PnI/QQIsIkb+J6YlMmPBe5'
bbs_secret_key = 'JHwmB38PU07I8d/Zvj/vE1NtjEzjziRTJ4zw09RiHWM='

message= {
    "owner": "Device1-admin",
    "measurements":{
        "temperature":"30oC",
        "humidity":"60%"
    }
}

frame ={
    "measurements":{
        "temperature":"",
    }
}

bbs_signer = Signer(public_key=base64.b64decode(bbs_public_key),secret_key=base64.b64decode(bbs_secret_key))
bbs_signature = bbs_signer.sign_json(json.dumps(message))
print(base64.b64encode(bbs_signature))
bbs_prover = Prover()
claims, revealed_message, zkp = bbs_prover.generate_zkp(public_key=base64.b64decode(bbs_public_key), message=json.dumps(message), frame=json.dumps(frame), signature=bbs_signature)
print(revealed_message)
print(base64.b64encode(zkp))
bbs_verifier = Verifier()
verification = bbs_verifier.verify_zkp(public_key=base64.b64decode(bbs_public_key), message=revealed_message, claims=claims, zkp=zkp )
print(verification)