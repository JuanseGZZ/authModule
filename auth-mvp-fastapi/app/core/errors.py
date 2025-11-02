from fastapi import HTTPException, status

class AuthErrorCodes:
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    AUTH_TOKEN_EXPIRED = "AUTH_TOKEN_EXPIRED"
    AUTH_TOKEN_REVOKED = "AUTH_TOKEN_REVOKED"
    AUTH_REFRESH_NOT_FOUND = "AUTH_REFRESH_NOT_FOUND"
    AUTH_RATE_LIMIT = "AUTH_RATE_LIMIT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    CONFLICT_EMAIL_TAKEN = "CONFLICT_EMAIL_TAKEN"

def http_401(code: str, message: str = "Unauthorized"):
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": {"code": code, "message": message}})

def http_409(code: str, message: str = "Conflict"):
    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error": {"code": code, "message": message}})

def http_429(code: str, message: str = "Too Many Requests"):
    raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": {"code": code, "message": message}})
