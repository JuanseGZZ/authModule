
from typing import Dict, Any
from fastapi import Request
from utils.crypto import decrypt_front_jwe

async def parse_front_encrypted(req: Request, data: Dict[str, Any]) -> Dict[str, Any]:
    # Si el cuerpo incluye "__front_enc__", se descifra antes de usar.
    if "__front_enc__" in data and isinstance(data["__front_enc__"], str):
        decrypted = decrypt_front_jwe(data["__front_enc__"])
        if not isinstance(decrypted, dict):
            # TODO: políticas de error exactas del YAML
            raise ValueError("Payload cifrado inválido")
        return decrypted
    return data


def bearer_token(req: Request) -> str | None:
    auth = req.headers.get("authorization") or req.headers.get("Authorization")
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip()
