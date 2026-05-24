"""Per-tenant query budget: prevents model extraction via volume."""
from __future__ import annotations

import time

import redis.asyncio as redis


class QueryBudget:
    def __init__(self, redis_client: redis.Redis,
                 daily_limit: int = 10_000):
        self.r = redis_client
        self.limit = daily_limit

    async def consume(self, tenant: str, n: int = 1) -> bool:
        """Returns True if within budget; False if exceeded."""
        key = f"budget:{tenant}:day"
        now = int(time.time())
        pipe = self.r.pipeline()
        pipe.incrby(key, n)
        pipe.expireat(key, now + 86400)
        used, _ = await pipe.execute()
        return int(used) <= self.limit

    async def remaining(self, tenant: str) -> int:
        used = int(await self.r.get(f"budget:{tenant}:day") or 0)
        return max(0, self.limit - used)
