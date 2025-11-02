
import time
from typing import Dict, Tuple
from fastapi import Request
from utils.errors import error_response

_buckets: Dict[Tuple[str, str], Tuple[int, int, float]] = {}

def parse_rule(rule: str):
    count, window = rule.split("/")
    return int(count), int(window)

def rate_limit(request: Request, rule: str, code="rate_limited", message="Too many requests"):
    ip = request.client.host if request.client else "anon"
    key = (ip, request.url.path)
    limit, window = parse_rule(rule)
    now = time.time()
    data = _buckets.get(key, (0, limit, now + window))
    count, limit_val, reset = data
    if now > reset:
        count = 0
        reset = now + window
    count += 1
    _buckets[key] = (count, limit, reset)
    if count > limit:
        return error_response(code, message, 429)
    return None
