import time
import threading
from typing import Dict, Any, Optional
from dataclasses import dataclass

from ml_model.feature_extractor import normalize_url
from .cache_policy import CachePolicy


@dataclass
class CacheEntry:
    """Internal representation of a cached analysis entry."""
    key: str
    value: dict
    model_version: str
    created_at: float
    expires_at: float
    last_accessed: float

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at


class MemoryCache:
    """Thread-safe, bounded, in-memory trust cache for Aegis analysis results."""

    def __init__(self, policy: Optional[CachePolicy] = None):
        self.policy = policy or CachePolicy()
        self._store: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()

    def _canonical_key(self, url: str) -> str:
        return normalize_url(url)

    def _cleanup_expired_locked(self, current_time: float) -> int:
        expired_keys = [
            k for k, entry in self._store.items()
            if entry.is_expired(current_time)
        ]
        for k in expired_keys:
            del self._store[k]
        return len(expired_keys)

    def _evict_if_full_locked(self, current_time: float) -> None:
        if len(self._store) < self.policy.max_entries:
            return

        # 1. Clean up expired entries first
        self._cleanup_expired_locked(current_time)

        # 2. If still at or over max_entries, evict least recently accessed (LRU)
        if len(self._store) >= self.policy.max_entries:
            lru_key = min(
                self._store.keys(),
                key=lambda k: self._store[k].last_accessed
            )
            del self._store[lru_key]

    def get(
        self, url: str, active_model_version: Optional[str] = None
    ) -> Optional[dict]:
        """Retrieve cached result if valid and unexpired."""
        key = self._canonical_key(url)
        now = time.time()
        target_model = active_model_version or self.policy.active_model_version

        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None

            # Check expiration
            if entry.is_expired(now):
                del self._store[key]
                return None

            # Check model version compatibility
            if target_model and entry.model_version != target_model:
                del self._store[key]
                return None

            # Update access timestamp
            entry.last_accessed = now

            result_copy = dict(entry.value)
            result_copy["cached"] = True
            return result_copy

    def set(
        self,
        url: str,
        value: dict,
        model_version: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store an analysis result in the cache."""
        key = self._canonical_key(url)
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.policy.ttl_seconds
        version = model_version or self.policy.active_model_version

        with self._lock:
            # Ensure space before inserting new key if key not already present
            if key not in self._store:
                self._evict_if_full_locked(now)

            expires_at = now + ttl
            self._store[key] = CacheEntry(
                key=key,
                value=dict(value),
                model_version=version,
                created_at=now,
                expires_at=expires_at,
                last_accessed=now,
            )

    def delete(self, url: str) -> bool:
        """Explicitly remove an entry by URL."""
        key = self._canonical_key(url)
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def invalidate_url(self, url: str) -> bool:
        """Alias for delete(url)."""
        return self.delete(url)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._store.clear()

    def contains(
        self, url: str, active_model_version: Optional[str] = None
    ) -> bool:
        """Check if a valid, unexpired entry exists for the given URL."""
        return self.get(url, active_model_version=active_model_version) is not None

    def size(self) -> int:
        """Return count of active (non-expired) entries."""
        now = time.time()
        with self._lock:
            self._cleanup_expired_locked(now)
            return len(self._store)
