package verifier

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
)

// cacheEntry wraps a verification result with expiration timestamp
type cacheEntry struct {
	result    common.VerificationResult
	expiresAt time.Time
}

// VerificationCache is a concurrent, thread-safe in-memory cache for verification results
type VerificationCache struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry
	ttl        time.Duration
	maxEntries int
	hits       uint64
	misses     uint64
}

// NewVerificationCache constructs a new cache instance
func NewVerificationCache(ttl time.Duration, maxEntries int) *VerificationCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 5000
	}
	return &VerificationCache{
		entries:    make(map[string]cacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// Get looks up a cached verification result by image identifier or digest
func (c *VerificationCache) Get(key string) (common.VerificationResult, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddUint64(&c.misses, 1)
		return common.VerificationResult{}, false
	}

	if time.Now().After(entry.expiresAt) {
		// Expired entry
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		atomic.AddUint64(&c.misses, 1)
		return common.VerificationResult{}, false
	}

	atomic.AddUint64(&c.hits, 1)
	return entry.result, true
}

// Set stores a verification result in the cache
func (c *VerificationCache) Set(key string, result common.VerificationResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if capacity reached: prune expired, or remove random element
	if len(c.entries) >= c.maxEntries {
		now := time.Now()
		evicted := false
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
				evicted = true
				break
			}
		}
		if !evicted {
			// Evict any entry if none expired
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}

	c.entries[key] = cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Stats returns the cache hit and miss count
func (c *VerificationCache) Stats() (hits uint64, misses uint64, size int) {
	c.mu.RLock()
	size = len(c.entries)
	c.mu.RUnlock()
	return atomic.LoadUint64(&c.hits), atomic.LoadUint64(&c.misses), size
}

// Clear flushes all entries from the cache
func (c *VerificationCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}
