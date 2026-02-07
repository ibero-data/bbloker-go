package bbloker

import (
	"net/http"
	"strings"
)

// Decision is the result of running a request through the detection pipeline.
type Decision struct {
	Action     string  // "block" or "allow"
	Reason     string  // "known_bot_ua", "known_bot_ip", "rate_limit", "header_anomaly", or ""
	Confidence float64 // 0.0–1.0
}

// Analyze runs the 5-check detection pipeline against the given request.
func (b *Bbloker) Analyze(r *http.Request) Decision {
	ip := extractIP(r)
	ua := r.Header.Get("User-Agent")
	headers := normalizeHeaders(r)

	// 1. UA check
	if b.rules.isBlockedUA(ua) {
		return Decision{Action: "block", Reason: "known_bot_ua", Confidence: 0.95}
	}

	// 2. IP check
	if b.rules.isBlockedIP(ip) {
		return Decision{Action: "block", Reason: "known_bot_ip", Confidence: 0.90}
	}

	// 3. Rate limit
	if b.limiter.isExceeded(ip) {
		return Decision{Action: "block", Reason: "rate_limit", Confidence: 0.70}
	}

	// 4. Header anomaly
	score := b.rules.headerAnomalyScore(headers)
	if score > b.rules.anomalyThreshold() {
		return Decision{Action: "block", Reason: "header_anomaly", Confidence: score}
	}

	// 5. Allow
	return Decision{Action: "allow"}
}

func normalizeHeaders(r *http.Request) map[string]string {
	h := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		h[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return h
}
