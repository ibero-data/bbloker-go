package bbloker

import (
	"sync"
	"time"
)

type window struct {
	count   int
	resetAt int64 // unix milliseconds
}

type rateLimiter struct {
	mu          sync.Mutex
	windows     map[string]*window
	maxRequests int
	windowMs    int64
}

func newRateLimiter(maxRequests int, windowDur time.Duration, done chan struct{}) *rateLimiter {
	rl := &rateLimiter{
		windows:     make(map[string]*window),
		maxRequests: maxRequests,
		windowMs:    windowDur.Milliseconds(),
	}

	// Cleanup goroutine removes expired windows every 60s.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	}()

	return rl
}

func (rl *rateLimiter) isExceeded(ip string) bool {
	now := time.Now().UnixMilli()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	w, ok := rl.windows[ip]
	if !ok || now >= w.resetAt {
		rl.windows[ip] = &window{count: 1, resetAt: now + rl.windowMs}
		return false
	}

	w.count++
	return w.count > rl.maxRequests
}

func (rl *rateLimiter) cleanup() {
	now := time.Now().UnixMilli()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ip, w := range rl.windows {
		if now >= w.resetAt {
			delete(rl.windows, ip)
		}
	}
}
