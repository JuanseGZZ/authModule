
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        dur_ms = int((time.time() - start) * 1000)
        path = request.url.path
        method = request.method
        status = response.status_code
        print(f"[AUDIT] {method} {path} -> {status} ({dur_ms}ms)")
        return response
