#!/usr/bin/env python3
"""
CHOMBEZA - Response Cache Module
Caches HTTP responses to avoid redundant requests
"""

import time
import hashlib
import logging
import threading
from typing import Dict, Optional, Any
from collections import OrderedDict
from dataclasses import dataclass, field

logger = logging.getLogger("CHOMBEZA.Cache")

@dataclass
class CachedResponse:
    """Represents a cached HTTP response"""
    content: bytes
    text: str
    status_code: int
    headers: Dict[str, str]
    url: str
    timestamp: float
    size: int
    hash: str = field(init=False)
    
    def __post_init__(self):
        self.hash = hashlib.md5(self.content).hexdigest()[:8]
    
    def is_expired(self, ttl: int) -> bool:
        """Check if cache entry is expired"""
        return time.time() - self.timestamp > ttl

class ResponseCache:
    """
    Thread-safe LRU cache for HTTP responses
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        """
        Initialize cache
        
        Args:
            max_size: Maximum number of entries to cache
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CachedResponse] = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        
        logger.debug(f"Cache initialized: max_size={max_size}, ttl={default_ttl}s")
    
    def get(self, key: str, ttl: Optional[int] = None) -> Optional[CachedResponse]:
        """
        Get cached response if exists and not expired
        
        Args:
            key: Cache key (usually URL hash)
            ttl: Optional custom TTL
            
        Returns:
            CachedResponse or None
        """
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                
                # Check expiration
                if entry.is_expired(ttl or self.default_ttl):
                    self._evict(key)
                    self.misses += 1
                    return None
                
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.hits += 1
                
                logger.debug(f"Cache hit: {key} (size: {entry.size} bytes)")
                return entry
            
            self.misses += 1
            return None
    
    def set(self, key: str, response: Any, ttl: Optional[int] = None):
        """
        Cache a response
        
        Args:
            key: Cache key
            response: requests.Response object
            ttl: Optional custom TTL (ignored, kept for compatibility)
        """
        if not response:
            return
        
        with self.lock:
            # Create cache entry
            cached = CachedResponse(
                content=response.content,
                text=response.text,
                status_code=response.status_code,
                headers=dict(response.headers),
                url=response.url,
                timestamp=time.time(),
                size=len(response.content) if response.content else 0
            )
            
            # Check if we need to evict oldest
            if len(self.cache) >= self.max_size:
                self._evict_oldest()
            
            self.cache[key] = cached
            self.cache.move_to_end(key)
            
            logger.debug(f"Cached: {key} (size: {cached.size} bytes)")
    
    def _evict(self, key: str):
        """Evict a specific key"""
        if key in self.cache:
            del self.cache[key]
            self.evictions += 1
            logger.debug(f"Evicted: {key}")
    
    def _evict_oldest(self):
        """Evict the oldest (least recently used) entry"""
        if self.cache:
            oldest_key = next(iter(self.cache))
            self._evict(oldest_key)
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0
            logger.info("Cache cleared")
    
    def invalidate_pattern(self, pattern: str):
        """Invalidate cache entries matching pattern in URL"""
        import re
        
        with self.lock:
            keys_to_remove = []
            for key, entry in self.cache.items():
                if re.search(pattern, entry.url, re.I):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self._evict(key)
            
            if keys_to_remove:
                logger.info(f"Invalidated {len(keys_to_remove)} entries matching '{pattern}'")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": f"{hit_rate:.1f}%",
                "entries": [
                    {
                        "key": k,
                        "url": v.url[:50] + "..." if len(v.url) > 50 else v.url,
                        "status": v.status_code,
                        "size": v.size,
                        "age": f"{time.time() - v.timestamp:.1f}s",
                        "hash": v.hash
                    }
                    for k, v in list(self.cache.items())[-10:]  # Last 10 entries
                ]
            }
    
    def prefetch(self, urls: list, fetcher: callable):
        """
        Prefetch URLs into cache
        
        Args:
            urls: List of URLs to prefetch
            fetcher: Function that takes URL and returns response
        """
        for url in urls:
            key = hashlib.md5(url.encode()).hexdigest()
            if key not in self.cache:
                try:
                    response = fetcher(url)
                    if response:
                        self.set(key, response)
                except Exception as e:
                    logger.debug(f"Prefetch failed for {url}: {e}")
    
    def get_size_bytes(self) -> int:
        """Get total size of cached responses in bytes"""
        with self.lock:
            return sum(entry.size for entry in self.cache.values())

# Global cache instance
_response_cache = None

def get_cache(max_size: int = 1000) -> ResponseCache:
    """Get or create global cache instance"""
    global _response_cache
    if _response_cache is None:
        _response_cache = ResponseCache(max_size)
    return _response_cache