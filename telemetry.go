package bbloker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type fingerprint struct {
	IP          string            `json:"ip"`
	UserAgent   string            `json:"userAgent"`
	HeaderOrder []string          `json:"headerOrder"`
	Headers     map[string]string `json:"headers"`
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Ts          float64           `json:"ts"`
}

type telemetryPayload struct {
	Events []fingerprint `json:"events"`
}

type telemetryClient struct {
	mu        sync.Mutex
	buffer    []fingerprint
	apiURL    string
	apiKey    string
	maxBuffer int
	enabled   bool
}

func newTelemetryClient(apiURL, apiKey string, maxBuffer int, enabled bool, interval time.Duration, done chan struct{}) *telemetryClient {
	tc := &telemetryClient{
		apiURL:    apiURL,
		apiKey:    apiKey,
		maxBuffer: maxBuffer,
		enabled:   enabled,
	}

	if !enabled {
		return tc
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				tc.flush()
			}
		}
	}()

	return tc
}

func (tc *telemetryClient) push(fp fingerprint) {
	if !tc.enabled {
		return
	}
	tc.mu.Lock()
	tc.buffer = append(tc.buffer, fp)
	shouldFlush := len(tc.buffer) >= tc.maxBuffer
	tc.mu.Unlock()

	if shouldFlush {
		go tc.flush()
	}
}

func (tc *telemetryClient) flush() {
	tc.mu.Lock()
	if len(tc.buffer) == 0 {
		tc.mu.Unlock()
		return
	}
	batch := tc.buffer
	tc.buffer = nil
	tc.mu.Unlock()

	body, err := json.Marshal(telemetryPayload{Events: batch})
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", tc.apiURL+"/v1/fingerprints", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tc.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// buildFingerprint creates a fingerprint from an HTTP request.
func buildFingerprint(r *http.Request) fingerprint {
	headers := make(map[string]string, len(r.Header))
	order := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		order = append(order, lk)
		headers[lk] = strings.Join(v, ", ")
	}
	sort.Strings(order)

	return fingerprint{
		IP:          extractIP(r),
		UserAgent:   r.Header.Get("User-Agent"),
		HeaderOrder: order,
		Headers:     headers,
		Path:        r.URL.Path,
		Method:      r.Method,
		Ts:          float64(time.Now().UnixMilli()),
	}
}
