//! LRU cache for artifacts.

use bytes::Bytes;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// Artifact cache entry
struct CacheEntry {
    content: Bytes,
    size: usize,
}

/// LRU cache for artifacts
pub struct ArtifactCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
    max_size_bytes: usize,
    current_size: Mutex<usize>,
}

impl ArtifactCache {
    /// Create new cache with max size in MB
    pub fn new(max_size_mb: usize) -> Self {
        let max_entries = NonZeroUsize::new(10000).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(max_entries)),
            max_size_bytes: max_size_mb * 1024 * 1024,
            current_size: Mutex::new(0),
        }
    }

    /// Get cached artifact
    pub fn get(&self, key: &str) -> Option<Bytes> {
        let mut cache = self.cache.lock().unwrap();
        cache.get(key).map(|entry| entry.content.clone())
    }

    /// Put artifact in cache
    pub fn put(&self, key: String, content: Bytes) {
        let size = content.len();

        // Evict entries if needed to make room
        self.evict_if_needed(size);

        let entry = CacheEntry { content, size };

        let mut cache = self.cache.lock().unwrap();
        let mut current_size = self.current_size.lock().unwrap();

        // If key already exists, subtract old size
        if let Some(old) = cache.peek(&key) {
            *current_size -= old.size;
        }

        cache.put(key, entry);
        *current_size += size;
    }

    /// Check if key exists in cache
    pub fn contains(&self, key: &str) -> bool {
        let cache = self.cache.lock().unwrap();
        cache.contains(key)
    }

    /// Evict entries until we have room
    fn evict_if_needed(&self, needed: usize) {
        let mut cache = self.cache.lock().unwrap();
        let mut current_size = self.current_size.lock().unwrap();

        while *current_size + needed > self.max_size_bytes {
            if let Some((_, entry)) = cache.pop_lru() {
                *current_size -= entry.size;
            } else {
                break;
            }
        }
    }

    /// Get current cache size in bytes
    pub fn size(&self) -> usize {
        *self.current_size.lock().unwrap()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
