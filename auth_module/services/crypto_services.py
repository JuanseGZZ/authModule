
import time, uuid, json
from typing import Dict
from utils.env import settings
from utils.crypto import public_jwk
from jwcrypto import jws, jwe
from services.key_stores import KeyStores

class TokenSigner:
    def __init__(self, ks: KeyStores):
        self.ks = ks

    def issue_access(self, sub: str, extra_claims: Dict | None = None) -> str:
        now = int(time.time())
        exp = now + settings.access_ttl
        jti = uuid.uuid4().hex
        claims = {
            "iss": settings.iss,
            "aud": settings.aud,
            "iat": now,
            "nbf": now - 1,
            "exp": exp,
            "jti": jti,
            "sub": sub,
        }
        if extra_claims:
            claims.update(extra_claims)

        # JWS (RS256)
        signer = jws.JWS(json.dumps(claims).encode())
        signer.add_signature(self.ks.sig, None, {"alg":"RS256","kid":self.ks.sig.key_id,"typ":"JWT"}, None)
        compact_jws = signer.serialize(compact=True)

        # JWE (RSA-OAEP-256 + A256GCM)
        enc = jwe.JWE(compact_jws.encode(), protected={"alg":"RSA-OAEP-256","enc":"A256GCM","kid":self.ks.enc.key_id,"cty":"JWT"})
        enc.add_recipient(self.ks.enc)
        return enc.serialize(compact=True)

    def verify_access(self, token: str) -> Dict:
        # Decrypt
        enc = jwe.JWE()
        enc.deserialize(token)
        enc.decrypt(self.ks.enc)
        # Verify
        verifier = jws.JWS()
        verifier.deserialize(enc.payload.decode())
        verifier.verify(self.ks.sig)
        return json.loads(verifier.payload.decode())

class FrontPayloadDecrypter:
    def __init__(self, ks: KeyStores):
        self.ks = ks

    def maybe_decrypt(self, obj: Dict) -> Dict:
        fed = obj.get("__front_enc__")
        if not fed:
            return obj
        # Expect a compact JWE in obj["__front_enc__"]["compact"]
        compact = fed.get("compact")
        if not compact:
            raise ValueError("front_enc_missing_compact")
        dec = jwe.JWE()
        dec.deserialize(compact)
        dec.decrypt(self.ks.front)
        plain = dec.payload.decode()
        return json.loads(plain)
