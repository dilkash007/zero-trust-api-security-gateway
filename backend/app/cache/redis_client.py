"""Production Redis client with graceful in-memory fallback.

This module provides:
  - Redis connection management with health checks
  - Sliding-window rate limiting (Redis primary, in-memory fallback)
  - IP block-list management
  - Token bucket helpers for burst protection

When REDIS_URL is not set or Redis is unreachable, all operations fall back
to a thread-safe in-memory store so the application continues running.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Optional, Tuple

logger = logging.getLogger("zero_trust.cache")

# ---------------------------------------------------------------------------
# Optional Redis dependency — graceful if not installed / not reachable
# ---------------------------------------------------------------------------
try:
    import redis  # type: ignore

    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False
    logger.warning("[CACHE] redis-py not installed — using in-memory rate limiter.")


class _InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter backed by in-memory deques.

    This is the fallback used in development / when Redis is unavailable.
    """

    def __init__(self) -> None:
        self._windows: dict = defaultdict(deque)
        self._lock = threading.Lock()
        self._blocked_ips: dict = {}  # ip -> unblock_at_epoch

    # ------------------------------------------------------------------
    # Sliding-window rate check
    # ------------------------------------------------------------------
    def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """Check whether key has exceeded the rate limit.

        Returns:
            (allowed: bool, requests_remaining: int)
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            window = self._windows[key]
            # Prune expired timestamps
            while window and window[0] < cutoff:
                window.popleft()

            count = len(window)
            if count >= limit:
                return False, 0

            window.append(now)
            return True, limit - count - 1

    # ------------------------------------------------------------------
    # IP block list
    # ------------------------------------------------------------------
    def block_ip(self, ip: str, duration_seconds: int = 3600) -> None:
        with self._lock:
            self._blocked_ips[ip] = time.time() + duration_seconds
        logger.warning("[RATE_LIMIT] Blocked IP %s for %ds", ip, duration_seconds)

    def is_ip_blocked(self, ip: str) -> bool:
        with self._lock:
            unblock_at = self._blocked_ips.get(ip)
            if unblock_at is None:
                return False
            if time.time() > unblock_at:
                del self._blocked_ips[ip]
                return False
            return True

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.pop(ip, None)

    def get_blocked_ips(self) -> list:
        now = time.time()
        with self._lock:
            active = []
            for ip, unblock_at in list(self._blocked_ips.items()):
                if now <= unblock_at:
                    active.append({"ip": ip, "remaining_seconds": int(unblock_at - now)})
                else:
                    self._blocked_ips.pop(ip, None)
            return active

    def clear_all(self) -> None:
        with self._lock:
            self._windows.clear()
            self._blocked_ips.clear()

    # ------------------------------------------------------------------
    # Generic key-value store (for miscellaneous caching)
    # ------------------------------------------------------------------
    def get(self, key: str) -> Optional[str]:
        return None  # Simplified — extend if needed

    def set(self, key: str, value: str, ex: int = 300) -> None:
        pass  # Simplified

    def ping(self) -> bool:
        return True


class _RedisRateLimiter:
    """Production Redis-backed sliding-window rate limiter.

    Uses Redis ZADD / ZREMRANGEBYSCORE for accurate sliding windows.
    """

    def __init__(self, client) -> None:
        self._r = client

    def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - window_seconds
        redis_key = f"rl:{key}"

        pipe = self._r.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        pipe.zcard(redis_key)
        pipe.zadd(redis_key, {str(now): now})
        pipe.expire(redis_key, window_seconds + 1)
        results = pipe.execute()

        count_before = results[1]  # count BEFORE current request
        if count_before >= limit:
            # Undo the zadd — request is rejected
            self._r.zrem(redis_key, str(now))
            return False, 0

        remaining = limit - count_before - 1
        return True, max(remaining, 0)

    def block_ip(self, ip: str, duration_seconds: int = 3600) -> None:
        self._r.setex(f"blocked_ip:{ip}", duration_seconds, "1")
        logger.warning("[RATE_LIMIT] Redis blocked IP %s for %ds", ip, duration_seconds)

    def is_ip_blocked(self, ip: str) -> bool:
        return bool(self._r.exists(f"blocked_ip:{ip}"))

    def unblock_ip(self, ip: str) -> None:
        self._r.delete(f"blocked_ip:{ip}")

    def get_blocked_ips(self) -> list:
        keys = self._r.keys("blocked_ip:*")
        res = []
        for k in keys:
            key_str = k.decode() if isinstance(k, bytes) else k
            ip = key_str.replace("blocked_ip:", "")
            ttl = self._r.ttl(k)
            res.append({"ip": ip, "remaining_seconds": max(ttl, 0)})
        return res

    def clear_all(self) -> None:
        self._r.flushdb()


    def get(self, key: str) -> Optional[str]:
        val = self._r.get(key)
        return val.decode() if isinstance(val, bytes) else val

    def set(self, key: str, value: str, ex: int = 300) -> None:
        self._r.setex(key, ex, value)

    def ping(self) -> bool:
        try:
            return self._r.ping()
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Factory — returns Redis or in-memory limiter depending on environment
# ---------------------------------------------------------------------------

_rate_limiter: Optional[object] = None
_init_lock = threading.Lock()


def _build_limiter():
    """Build and cache the best available rate limiter."""
    global _rate_limiter

    if _rate_limiter is not None:
        return _rate_limiter

    with _init_lock:
        if _rate_limiter is not None:
            return _rate_limiter

        if _REDIS_AVAILABLE:
            try:
                from app.config import settings  # lazy import to avoid circular deps

                redis_url = getattr(settings, "REDIS_URL", None)
                if redis_url:
                    client = redis.from_url(redis_url, decode_responses=False, socket_timeout=2)
                    client.ping()
                    _rate_limiter = _RedisRateLimiter(client)
                    logger.info("[CACHE] Redis rate limiter initialized at %s", redis_url)
                    return _rate_limiter
            except Exception as exc:
                logger.warning("[CACHE] Redis unavailable (%s) — falling back to in-memory.", exc)

        _rate_limiter = _InMemoryRateLimiter()
        logger.info("[CACHE] In-memory rate limiter initialized.")
        return _rate_limiter


def get_rate_limiter():
    """Returns the active rate limiter (Redis or in-memory fallback)."""
    return _build_limiter()
