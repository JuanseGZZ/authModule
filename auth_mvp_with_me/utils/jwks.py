
import os, json
from typing import Dict, Any
from utils.crypto import get_keys

def get_public_jwks() -> Dict[str, Any]:
    keys = get_keys()
    # Solo claves públicas en formato JWKS
    return {"keys": [keys["sig"]["public_jwk"], keys["enc"]["public_jwk"], keys["enc_front"]["public_jwk"]]}

def get_active_kids():
    keys = get_keys()
    return {"sig": keys["sig"]["kid"], "enc": keys["enc"]["kid"], "enc_front": keys["enc_front"]["kid"]}
