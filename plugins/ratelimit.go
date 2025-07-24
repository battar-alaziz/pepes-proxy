package plugins

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// RateLimitPlugin handles rate limiting
type RateLimitPlugin struct {
	limiters map[string]*RateLimiter
	mutex    sync.RWMutex
}

type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	mutex    sync.Mutex
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Clean old requests
	if requests, exists := rl.requests[clientID]; exists {
		var validRequests []time.Time
		for _, reqTime := range requests {
			if reqTime.After(windowStart) {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.requests[clientID] = validRequests
	}

	// Check if limit exceeded
	if len(rl.requests[clientID]) >= rl.limit {
		return false
	}

	// Add current request
	rl.requests[clientID] = append(rl.requests[clientID], now)
	return true
}

func (p *RateLimitPlugin) Execute(ctx *PluginContext) *PluginResult {
	envs := parseEnvs(ctx.Envs)

	// Get rate limit configuration
	limitStr := envs["rate_limit"]
	windowStr := envs["rate_window"]

	if limitStr == "" {
		return &PluginResult{Success: true} // No rate limit configured
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("invalid rate_limit value: %v", err),
			HTTPStatusCode: 500,
		}
	}

	window := 60 * time.Second // Default 1 minute
	if windowStr != "" {
		if windowSec, err := strconv.Atoi(windowStr); err == nil {
			window = time.Duration(windowSec) * time.Second
		}
	}

	// Get or create rate limiter
	p.mutex.Lock()
	if p.limiters == nil {
		p.limiters = make(map[string]*RateLimiter)
	}

	key := fmt.Sprintf("%d_%v", limit, window)
	limiter, exists := p.limiters[key]
	if !exists {
		limiter = NewRateLimiter(limit, window)
		p.limiters[key] = limiter
	}
	p.mutex.Unlock()

	// Use client IP as identifier
	clientID := ctx.ClientIP

	if !limiter.Allow(clientID) {
		return &PluginResult{
			Success:        false,
			Error:          fmt.Errorf("rate limit exceeded"),
			HTTPStatusCode: 429,
		}
	}

	return &PluginResult{Success: true}
}
