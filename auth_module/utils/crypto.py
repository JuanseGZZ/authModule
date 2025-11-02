
import os, json
from jwcrypto import jwk, jws, jwe

def load_or_generate_keypair(path_priv: str, kty: str, use: str, kid: str) -> jwk.JWK:
    os.makedirs(os.path.dirname(path_priv), exist_ok=True)
    if os.path.exists(path_priv):
        with open(path_priv, "r") as f:
            return jwk.JWK.from_json(f.read())
    if kty == "RSA":
        key = jwk.JWK.generate(kty="RSA", size=2048, use=use, kid=kid)
    elif kty == "EC":
        key = jwk.JWK.generate(kty="EC", crv="P-256", use=use, kid=kid)
    else:
        raise ValueError("Unsupported kty")
    with open(path_priv, "w") as f:
        f.write(key.export(private_key=True))
    return key

def public_jwk(key: jwk.JWK) -> dict:
    return json.loads(key.export(private_key=False))
