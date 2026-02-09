"""Shared caching configuration for AWS documentation requests."""

import requests_cache
from pathlib import Path

CACHE_DIR = Path(__file__).parent / ".cache"
CACHE_DIR.mkdir(exist_ok=True)

def get_cached_session(expire_after: int = 86400) -> requests_cache.CachedSession:
    """Get a cached requests session. Default expiry: 24 hours."""
    return requests_cache.CachedSession(
        cache_name=str(CACHE_DIR / "aws_docs_cache"),
        backend="sqlite",
        expire_after=expire_after,
    )
