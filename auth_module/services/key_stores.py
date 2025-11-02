
import os, json
from typing import Dict
from jwcrypto import jwk
from utils.env import settings
from utils.crypto import load_or_generate_keypair, public_jwk

class KeyStores:
    def __init__(self):
        self.sig_active_kid = settings.jwks_sig_kid
        self.enc_active_kid = settings.jwks_enc_kid
        self.front_active_kid = settings.jwks_front_kid
        self.keys_dir = settings.keys_dir

        self.sig = self._load("RSA", "sig", self.sig_active_kid)
        self.enc = self._load("RSA", "enc", self.enc_active_kid)
        self.front = self._load("RSA", "enc", self.front_active_kid)  # enc_front

        self._grace_pub: Dict[str, Dict] = {}  # TODO per YAML (overlap_grace)

    def _load(self, kty: str, use: str, kid: str) -> jwk.JWK:
        path = os.path.join(self.keys_dir, f"{kid}.json")
        return load_or_generate_keypair(path, kty, use, kid)

    def jwks_public(self) -> Dict:
        keys = []
        s = public_jwk(self.sig); s["use"] = "sig"; keys.append(s)
        e = public_jwk(self.enc); e["use"] = "enc"; keys.append(e)
        f = public_jwk(self.front); f["use"] = "enc"; f["kid"] = self.front_active_kid; keys.append(f)
        keys.extend(self._grace_pub.values())
        return {"keys": keys}
