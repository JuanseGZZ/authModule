
from fastapi import APIRouter
from services.key_stores import KeyStores

router = APIRouter()
ks = KeyStores()

@router.get("/.well-known/jwks.json", tags=["jwks"])
def get_jwks():
    return ks.jwks_public()
