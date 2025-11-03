
from fastapi import APIRouter
from utils.jwks import get_public_jwks

router = APIRouter()

@router.get("/.well-known/jwks.json")
async def jwks():
    return get_public_jwks()
