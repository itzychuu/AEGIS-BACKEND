import time
import threading
import pytest

from cache.memory_cache import MemoryCache, CacheEntry
from cache.cache_policy import CachePolicy


def test_empty_cache_returns_miss():
    """1. Test that looking up a non-existent key returns None (miss)."""
    cache = MemoryCache()
    assert cache.get("https://example.com") is None
    assert cache.contains("https://example.com") is False


def test_set_then_get_returns_value():
    """2 & 3. Test set then get returns cached value with cached=True."""
    cache = MemoryCache()
    url = "https://example.com"
    data = {"classification": "SAFE", "risk_score": 5}

    cache.set(url, data, model_version="xgboost_v6")
    cached = cache.get(url, active_model_version="xgboost_v6")

    assert cached is not None
    assert cached["classification"] == "SAFE"
    assert cached["risk_score"] == 5
    assert cached["cached"] is True


def test_cache_expiration():
    """4, 5 & 6. Test that entries expire after TTL and are removed."""
    policy = CachePolicy(ttl_seconds=1)
    cache = MemoryCache(policy=policy)
    url = "https://example.com"
    data = {"classification": "SAFE", "risk_score": 5}

    cache.set(url, data, model_version="xgboost_v6")
    assert cache.get(url) is not None

    # Wait for TTL expiration
    time.sleep(1.1)

    # Expired entry must return None and be removed
    assert cache.get(url) is None
    assert cache.contains(url) is False
    assert cache.size() == 0


def test_delete():
    """7. Test explicit delete and invalidate_url."""
    cache = MemoryCache()
    url = "https://example.com"
    cache.set(url, {"classification": "SAFE"}, model_version="xgboost_v6")

    assert cache.contains(url) is True
    deleted = cache.delete(url)
    assert deleted is True
    assert cache.contains(url) is False

    # Deleting non-existent key returns False
    assert cache.delete(url) is False


def test_clear():
    """8. Test clear removes all entries."""
    cache = MemoryCache()
    cache.set("https://site1.com", {"val": 1}, model_version="xgboost_v6")
    cache.set("https://site2.com", {"val": 2}, model_version="xgboost_v6")

    assert cache.size() == 2
    cache.clear()
    assert cache.size() == 0
    assert cache.get("https://site1.com") is None


def test_url_normalization_cache_keys():
    """9. Test that different representations of same URL resolve to same cache key."""
    cache = MemoryCache()
    url1 = "example.com"
    url2 = "https://example.com"
    url3 = "  HTTPS://EXAMPLE.COM  "

    cache.set(url1, {"classification": "SAFE"}, model_version="xgboost_v6")

    assert cache.get(url2) is not None
    assert cache.get(url3) is not None
    assert cache.get(url2)["classification"] == "SAFE"


def test_different_urls_different_entries():
    """10. Test that distinct URLs have distinct entries."""
    cache = MemoryCache()
    cache.set("https://site-a.com", {"risk": 10}, model_version="xgboost_v6")
    cache.set("https://site-b.com", {"risk": 90}, model_version="xgboost_v6")

    res_a = cache.get("https://site-a.com")
    res_b = cache.get("https://site-b.com")

    assert res_a["risk"] == 10
    assert res_b["risk"] == 90


def test_model_version_mismatch_invalidation():
    """11. Test that model version mismatch invalidates cache entry."""
    cache = MemoryCache()
    url = "https://example.com"

    cache.set(url, {"classification": "SAFE"}, model_version="xgboost_v5")

    # Accessing with active_model_version="xgboost_v6" must return None and purge v5
    assert cache.get(url, active_model_version="xgboost_v6") is None
    assert cache.contains(url, active_model_version="xgboost_v6") is False


def test_max_cache_size_eviction():
    """12. Test that maximum cache size is enforced using eviction."""
    policy = CachePolicy(max_entries=3)
    cache = MemoryCache(policy=policy)

    cache.set("https://site1.com", {"id": 1}, model_version="xgboost_v6")
    cache.set("https://site2.com", {"id": 2}, model_version="xgboost_v6")
    cache.set("https://site3.com", {"id": 3}, model_version="xgboost_v6")
    assert cache.size() == 3

    # Inserting 4th item forces eviction
    cache.set("https://site4.com", {"id": 4}, model_version="xgboost_v6")
    assert cache.size() == 3
    assert cache.get("https://site4.com") is not None


def test_concurrent_cache_access():
    """13. Test concurrent reads and writes to memory cache."""
    cache = MemoryCache()
    errors = []

    def writer(start_idx):
        for i in range(start_idx, start_idx + 50):
            url = f"https://example-{i}.com"
            cache.set(url, {"idx": i}, model_version="xgboost_v6")

    def reader(start_idx):
        for i in range(start_idx, start_idx + 50):
            url = f"https://example-{i}.com"
            try:
                cache.get(url)
            except Exception as e:
                errors.append(e)

    threads = []
    for t in range(4):
        tw = threading.Thread(target=writer, args=(t * 50,))
        tr = threading.Thread(target=reader, args=(t * 50,))
        threads.extend([tw, tr])

    for th in threads:
        th.start()
    for th in threads:
        th.join()

    assert len(errors) == 0


def test_ttl_configuration():
    """14. Test custom TTL policy settings."""
    policy = CachePolicy(ttl_seconds=500, max_entries=200)
    assert policy.ttl_seconds == 500
    assert policy.max_entries == 200

    with pytest.raises(ValueError):
        CachePolicy(ttl_seconds=0)

    with pytest.raises(ValueError):
        CachePolicy(max_entries=-1)
