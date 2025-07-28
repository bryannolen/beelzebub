// package limiter is a simple, bucket based request limiter.
package limiter

import (
	"sync"
	"time"
)

// RateLimit struct contains the core variables used by the limiter.
type RateLimit struct {
	lastRefillTime time.Time
	tokens         float64
	maxTokens      float64
	refillRate     float64
	mu             sync.Mutex
}

// RateLimiter is a multi purpose, simple to use rate limiter that supports
// limiting per "key", where "key" is usually an IP address string, or IP:User compound key.
type RateLimiter struct {
	baseLimits *RateLimit // Used to store the default values for all dynamically created rateLimits in the map.
	rateLimits map[string]*RateLimit
	mu         sync.Mutex
}

// NewRateLimiter returns a RateLimiter configured with provided values.
func NewRateLimiter(epsLimit int) *RateLimiter {
	maxTokens := 0.0
	refillRate := 0.0

	if epsLimit > 0 {
		// Example: eps of 10 means 10 tokens refreshed per second, but a burst of 100 tokens.
		maxTokens = float64(epsLimit * 10)
		refillRate = float64(epsLimit)
	}

	return &RateLimiter{
		baseLimits: &RateLimit{
			tokens:         maxTokens,
			maxTokens:      maxTokens,
			refillRate:     refillRate,
			lastRefillTime: time.Now(),
		},
		rateLimits: make(map[string]*RateLimit),
	}
}

// Copy returns a new RateLimit with the same base values, suitable for adding to the rateLimits map.
func (l *RateLimit) Copy() *RateLimit {
	l.mu.Lock()
	defer l.mu.Unlock()

	return &RateLimit{
		lastRefillTime: time.Now(),
		tokens:         l.tokens,
		maxTokens:      l.maxTokens,
		refillRate:     l.refillRate,
	}
}

// Tokens returns the number of tokens available for this RateLimit.
func (l *RateLimit) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.tokens
}

func (l *RateLimit) refill() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastRefillTime).Seconds()

	l.tokens = l.tokens + elapsed*l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.lastRefillTime = now
}

// Allowed returns true when there are sufficient tokens for the provided "key".
func (rl *RateLimiter) Allowed(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.baseLimits.Tokens() == float64(0) {
		// No limit applied, so always allowed.
		return true
	}

	l, ok := rl.rateLimits[key]
	if !ok {
		// We have not seen this key before, so init a new entry in the map and return true.
		rl.rateLimits[key] = rl.baseLimits.Copy()
		return true
	}

	l.refill()
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}
