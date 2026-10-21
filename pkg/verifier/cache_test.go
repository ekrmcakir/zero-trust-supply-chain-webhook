package verifier

import (
	"sync"
	"testing"
	"time"

	"github.com/ekrmcakir/zero-trust-supply-chain-webhook/pkg/common"
	"github.com/stretchr/testify/assert"
)

func TestVerificationCache_Basic(t *testing.T) {
	cache := NewVerificationCache(100*time.Millisecond, 2)

	res := common.VerificationResult{
		Allowed: true,
		Reason:  common.ReasonAllowed,
		Image:   "ghcr.io/ekrmcakir/app:v1",
	}

	// Initial get: miss
	_, found := cache.Get("key1")
	assert.False(t, found)

	// Set & Get: hit
	cache.Set("key1", res)
	got, found := cache.Get("key1")
	assert.True(t, found)
	assert.Equal(t, res.Image, got.Image)

	hits, misses, size := cache.Stats()
	assert.Equal(t, uint64(1), hits)
	assert.Equal(t, uint64(1), misses)
	assert.Equal(t, 1, size)

	// Sleep until expiration
	time.Sleep(120 * time.Millisecond)
	_, found = cache.Get("key1")
	assert.False(t, found, "Expected entry to be expired")
}

func TestVerificationCache_Concurrency(t *testing.T) {
	cache := NewVerificationCache(5*time.Minute, 100)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "image-key"
			cache.Set(key, common.VerificationResult{Allowed: true})
			_, _ = cache.Get(key)
		}(i)
	}

	wg.Wait()
	hits, _, size := cache.Stats()
	assert.True(t, hits > 0)
	assert.Equal(t, 1, size)
}

func TestVerificationCache_EvictionAndClear(t *testing.T) {
	// Test default parameters when <= 0
	defCache := NewVerificationCache(0, 0)
	assert.NotNil(t, defCache)

	// Test capacity eviction
	cache := NewVerificationCache(1*time.Minute, 2)
	cache.Set("img1", common.VerificationResult{Allowed: true, Image: "img1"})
	cache.Set("img2", common.VerificationResult{Allowed: true, Image: "img2"})
	// 3rd item triggers eviction of an existing item
	cache.Set("img3", common.VerificationResult{Allowed: true, Image: "img3"})

	_, _, size := cache.Stats()
	assert.LessOrEqual(t, size, 2)

	// Test Clear
	cache.Clear()
	_, _, sizeAfterClear := cache.Stats()
	assert.Equal(t, 0, sizeAfterClear)
}

