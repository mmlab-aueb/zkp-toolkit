import json
from canonicalization import JCan
from ursa_bbs_signatures import BlsKeyPair, VerifyProofRequest, verify_proof

class Verifier:
    def verify_zkp(self,public_key: bytes, message:str, claims:int, zkp:bytes) -> bool:
        bls_pub_key = BlsKeyPair(public_key=public_key)
        revealed_messages = JCan(json.loads(message))
        bbs_pub_key = bls_pub_key.get_bbs_key(claims)
        proof_verify_request = VerifyProofRequest(public_key=bbs_pub_key,
                                          proof=zkp,
                                          messages=revealed_messages,
                                          nonce=b'PROOF_NONCE')#<---fix that
    
        proof_verify_res = verify_proof(proof_verify_request)
        return proof_verify_res