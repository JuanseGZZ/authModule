
from fastapi.responses import JSONResponse

def error_response(code: str, message: str, status: int = 400):
    payload = {"error": {"code": code, "message": message}}
    return JSONResponse(status_code=status, content=payload)
