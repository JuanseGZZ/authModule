from collections import defaultdict, deque
from time import time

# Simple in-memory rate limiter (MVP). Consider Redis for prod.
WINDOW = 900  # 15m

class RateLimiter:
    def __init__(self, limit: int):
        self.limit = limit
        self.hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time()
        q = self.hits[key]
        while q and now - q[0] > WINDOW:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True
