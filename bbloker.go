package bbloker

import (
	"net/http"
	"time"
)

// Config holds all settings for the bbloker middleware.
type Config struct {
	// API key from the bbloker dashboard (bb-sk-xxx). Required.
	APIKey string

	// API endpoint. Default: "https://bbloker.com"
	APIURL string

	// Rule sync interval. Default: 5 * time.Minute
	SyncInterval time.Duration

	// Telemetry flush interval. Default: 10 * time.Second
	FlushInterval time.Duration

	// Max fingerprints to buffer before force flush. Default: 100
	BufferSize int

	// Enable telemetry reporting. Default: true
	Telemetry *bool

	// Rate limit: max requests per IP per window. Default: 60
	RateLimit int

	// Rate limit window duration. Default: 60 * time.Second
	RateLimitWindow time.Duration

	// Custom block handler. Default: 403 Forbidden with no body.
	OnBlock func(w http.ResponseWriter, r *http.Request, d Decision)
}

// Bbloker is the main client. Create one with New() and attach it as
// middleware via Handler.
type Bbloker struct {
	config    Config
	rules     *ruleManager
	telemetry *telemetryClient
	limiter   *rateLimiter
	done      chan struct{}
}

// New creates a Bbloker instance, applies defaults, and starts background
// goroutines for rule syncing, telemetry flushing, and rate-limit cleanup.
func New(cfg Config) *Bbloker {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://bbloker.com"
	}
	if cfg.SyncInterval == 0 {
		cfg.SyncInterval = 5 * time.Minute
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 100
	}
	if cfg.Telemetry == nil {
		t := true
		cfg.Telemetry = &t
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 60
	}
	if cfg.RateLimitWindow == 0 {
		cfg.RateLimitWindow = 60 * time.Second
	}

	done := make(chan struct{})

	rm := newRuleManager(cfg.APIURL, cfg.APIKey, cfg.SyncInterval, done)
	tc := newTelemetryClient(cfg.APIURL, cfg.APIKey, cfg.BufferSize, *cfg.Telemetry, cfg.FlushInterval, done)
	rl := newRateLimiter(cfg.RateLimit, cfg.RateLimitWindow, done)

	return &Bbloker{
		config:    cfg,
		rules:     rm,
		telemetry: tc,
		limiter:   rl,
		done:      done,
	}
}

// Close stops all background goroutines and flushes remaining telemetry.
func (b *Bbloker) Close() {
	close(b.done)
	b.telemetry.flush()
}
