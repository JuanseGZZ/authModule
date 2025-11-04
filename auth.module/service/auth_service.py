from typing import Tuple, Dict, Any

def login(identifier: str, password: str) -> Tuple[str, str, Dict[str, Any]]:
    raise NotImplementedError()

def refresh(refresh_token_raw: str) -> Tuple[str, str | None]:
    raise NotImplementedError()

def logout(jti: str) -> None:
    raise NotImplementedError()

def verify(access_token_raw: str) -> Dict[str, Any]:
    raise NotImplementedError()
