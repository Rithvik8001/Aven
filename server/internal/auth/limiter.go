package auth

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LimiterConfig controls one token bucket policy.
type LimiterConfig struct {
	Capacity   int
	RefillRate time.Duration
	IdleAfter  time.Duration
}

// Limiter is a small in-memory token-bucket limiter. It is intentionally
// process-local; a shared store is needed when the API runs on multiple nodes.
type Limiter struct {
	mu        sync.Mutex
	capacity  float64
	rate      float64
	idleAfter time.Duration
	buckets   map[string]bucket
}

const maxBuckets = 10_000

type bucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

// NewLimiter builds a limiter with a full bucket for every new key.
func NewLimiter(cfg LimiterConfig) (*Limiter, error) {
	if cfg.Capacity <= 0 {
		return nil, errors.New("auth: rate-limit capacity must be positive")
	}
	if cfg.RefillRate <= 0 {
		return nil, errors.New("auth: rate-limit refill interval must be positive")
	}
	if cfg.IdleAfter <= 0 {
		cfg.IdleAfter = 10 * cfg.RefillRate
	}

	return &Limiter{
		capacity:  float64(cfg.Capacity),
		rate:      float64(cfg.Capacity) / cfg.RefillRate.Seconds(),
		idleAfter: cfg.IdleAfter,
		buckets:   make(map[string]bucket),
	}, nil
}

// Allow consumes one token and reports how long a rejected caller should wait.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.removeIdle(now)
	current, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.removeOldest()
		}
		l.buckets[key] = bucket{tokens: l.capacity - 1, updated: now, lastSeen: now}
		return true, 0
	}

	if elapsed := now.Sub(current.updated).Seconds(); elapsed > 0 {
		current.tokens = math.Min(l.capacity, current.tokens+elapsed*l.rate)
		current.updated = now
	}
	current.lastSeen = now

	if current.tokens >= 1 {
		current.tokens--
		l.buckets[key] = current
		return true, 0
	}

	l.buckets[key] = current
	wait := time.Duration(math.Ceil((1-current.tokens)/l.rate) * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

func (l *Limiter) removeIdle(now time.Time) {
	for key, current := range l.buckets {
		if now.Sub(current.lastSeen) > l.idleAfter {
			delete(l.buckets, key)
		}
	}
}

func (l *Limiter) removeOldest() {
	var oldestKey string
	var oldest time.Time
	for key, current := range l.buckets {
		if oldestKey == "" || current.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = current.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

// ClientIP returns the network address used for rate limiting. Forwarded
// headers are intentionally ignored until trusted proxy configuration exists.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	if value := strings.TrimSpace(r.RemoteAddr); value != "" {
		return value
	}
	return "unknown"
}
