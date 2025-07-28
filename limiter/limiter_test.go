package limiter

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewRateLimiter(t *testing.T) {
	t.Run("With positive limit", func(t *testing.T) {
		epsLimit := 10
		rl := NewRateLimiter(epsLimit)

		assert.NotNil(t, rl)
		assert.NotNil(t, rl.baseLimits)
		assert.Equal(t, float64(epsLimit*10), rl.baseLimits.maxTokens)
		assert.Equal(t, float64(epsLimit*10), rl.baseLimits.tokens)
		assert.Equal(t, float64(epsLimit), rl.baseLimits.refillRate)
		assert.NotNil(t, rl.rateLimits)
		assert.Empty(t, rl.rateLimits)
	})

	t.Run("With zero limit", func(t *testing.T) {
		epsLimit := 0
		rl := NewRateLimiter(epsLimit)

		assert.NotNil(t, rl)
		assert.NotNil(t, rl.baseLimits)
		assert.Equal(t, 0.0, rl.baseLimits.maxTokens)
		assert.Equal(t, 0.0, rl.baseLimits.tokens)
		assert.Equal(t, 0.0, rl.baseLimits.refillRate)
		assert.NotNil(t, rl.rateLimits)
		assert.Empty(t, rl.rateLimits)
	})

	t.Run("With negative limit", func(t *testing.T) {
		epsLimit := -5
		rl := NewRateLimiter(epsLimit)

		assert.NotNil(t, rl)
		assert.NotNil(t, rl.baseLimits)
		assert.Equal(t, 0.0, rl.baseLimits.maxTokens)
		assert.Equal(t, 0.0, rl.baseLimits.tokens)
		assert.Equal(t, 0.0, rl.baseLimits.refillRate)
		assert.NotNil(t, rl.rateLimits)
		assert.Empty(t, rl.rateLimits)
	})
}

func TestRateLimit_Copy(t *testing.T) {
	original := &RateLimit{
		lastRefillTime: time.Now().Add(-1 * time.Hour),
		tokens:         50,
		maxTokens:      100,
		refillRate:     10,
	}

	copied := original.Copy()

	assert.NotNil(t, copied)
	assert.NotSame(t, original, copied)
	assert.Equal(t, original.tokens, copied.tokens)
	assert.Equal(t, original.maxTokens, copied.maxTokens)
	assert.Equal(t, original.refillRate, copied.refillRate)
	// lastRefillTime should be reset to time.Now()
	assert.WithinDuration(t, time.Now(), copied.lastRefillTime, time.Second)
}

func TestRateLimit_Tokens(t *testing.T) {
	l := &RateLimit{
		tokens: 50,
		mu:     sync.Mutex{},
	}

	assert.Equal(t, 50.0, l.Tokens())
}

func TestRateLimiter_Allowed(t *testing.T) {
	t.Run("No limit", func(t *testing.T) {
		rl := NewRateLimiter(0)
		assert.True(t, rl.Allowed("any_key"))
		assert.True(t, rl.Allowed("any_other_key"))
	})

	t.Run("With limit - basic", func(t *testing.T) {
		rl := NewRateLimiter(100) // 100 eps, 1000 max tokens
		key := "127.0.0.1"

		// First call for a new key should be allowed
		assert.True(t, rl.Allowed(key))
		assert.Contains(t, rl.rateLimits, key)

		// Exhaust initial tokens. The copy has 1000 tokens.
		for i := range 1000 {
			assert.True(t, rl.Allowed(key), "should be allowed on iteration %d", i)
		}

		// The next one should fail
		assert.False(t, rl.Allowed(key))
	})

	t.Run("With limit - refill", func(t *testing.T) {
		// 1 token per second, 10 max tokens
		rl := NewRateLimiter(1)
		key := "127.0.0.1"

		// First call is always true and creates the limiter
		assert.True(t, rl.Allowed(key))

		// Exhaust tokens (9 left)
		for range 10 {
			assert.True(t, rl.Allowed(key))
		}

		// Now it should be exhausted
		assert.False(t, rl.Allowed(key))

		// Wait for 2 seconds to get 2 new tokens
		time.Sleep(2 * time.Second)

		// Should be allowed again
		assert.True(t, rl.Allowed(key))
		assert.True(t, rl.Allowed(key))
		assert.False(t, rl.Allowed(key))
	})

	t.Run("With limit - multiple keys", func(t *testing.T) {
		rl := NewRateLimiter(1) // 1 token/sec, 10 max
		key1 := "192.168.1.1"
		key2 := "192.168.1.2"

		// Exhaust key1
		for range 11 {
			assert.True(t, rl.Allowed(key1))
		}
		assert.False(t, rl.Allowed(key1))

		// key2 should still be allowed
		assert.True(t, rl.Allowed(key2))
	})
}
