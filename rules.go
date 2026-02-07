package bbloker

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HeaderPattern defines a regex pattern for detecting header anomalies.
type HeaderPattern struct {
	Name    string  `json:"name"`
	Pattern string  `json:"pattern"`
	Weight  float64 `json:"weight"`
}

// RuleSet is the full set of detection rules, fetched from the API or
// falling back to hardcoded defaults.
type RuleSet struct {
	Version          uint64          `json:"version"`
	UpdatedAt        string          `json:"updatedAt"`
	BlockedUAs       []string        `json:"blockedUAs"`
	BlockedIPs       []string        `json:"blockedIPs"`
	HeaderPatterns   []HeaderPattern `json:"headerPatterns"`
	AnomalyThreshold float64        `json:"anomalyThreshold"`
}

var defaultRules = RuleSet{
	Version:   1,
	UpdatedAt: "2026-02-06",
	BlockedUAs: []string{
		"GPTBot", "ChatGPT-User", "OAI-SearchBot",
		"CCBot",
		"anthropic-ai", "ClaudeBot", "Claude-Web",
		"Meta-ExternalAgent", "Meta-ExternalFetcher", "FacebookBot",
		"facebookexternalhit",
		"PerplexityBot",
		"Bytespider",
		"Google-Extended",
		"Applebot-Extended",
		"cohere-ai",
		"Diffbot",
		"ImagesiftBot",
		"Omgilibot",
		"Omgili",
		"YouBot",
		"Amazonbot",
		"AI2Bot", "Ai2Bot-Dolma",
		"Scrapy",
		"PetalBot",
		"Semrushbot",
		"AhrefsBot",
		"MJ12bot",
		"DotBot",
		"Seekport",
		"BLEXBot",
		"DataForSeoBot",
		"magpie-crawler",
		"Timpibot",
		"Velenpublicwebcrawler",
		"Webzio-Extended",
		"iaskspider",
		"Kangaroo Bot",
		"img2dataset",
	},
	BlockedIPs: []string{
		"20.15.240.0/20",
		"20.171.206.0/23",
		"40.83.2.0/23",
		"52.230.152.0/21",
		"20.171.207.0/24",
	},
	HeaderPatterns: []HeaderPattern{
		{Name: "accept", Pattern: `^\*\/\*$`, Weight: 0.3},
		{Name: "accept-language", Pattern: `^$`, Weight: 0.5},
		{Name: "accept-encoding", Pattern: `^$`, Weight: 0.4},
	},
	AnomalyThreshold: 0.7,
}

type ruleManager struct {
	mu      sync.RWMutex
	current RuleSet
	// Pre-lowercased UA patterns for fast substring matching.
	uaLower []string
	// Compiled header-anomaly regexes, parallel to current.HeaderPatterns.
	headerRe []*regexp.Regexp

	apiURL string
	apiKey string
}

func newRuleManager(apiURL, apiKey string, interval time.Duration, done chan struct{}) *ruleManager {
	rm := &ruleManager{
		apiURL: apiURL,
		apiKey: apiKey,
	}
	rm.applyRules(defaultRules)

	// Kick off first sync immediately, then on ticker.
	go func() {
		rm.syncOnce()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				rm.syncOnce()
			}
		}
	}()

	return rm
}

func (rm *ruleManager) applyRules(rs RuleSet) {
	lower := make([]string, len(rs.BlockedUAs))
	for i, ua := range rs.BlockedUAs {
		lower[i] = strings.ToLower(ua)
	}

	compiled := make([]*regexp.Regexp, len(rs.HeaderPatterns))
	for i, hp := range rs.HeaderPatterns {
		re, err := regexp.Compile(hp.Pattern)
		if err != nil {
			continue
		}
		compiled[i] = re
	}

	rm.mu.Lock()
	rm.current = rs
	rm.uaLower = lower
	rm.headerRe = compiled
	rm.mu.Unlock()
}

func (rm *ruleManager) syncOnce() {
	req, err := http.NewRequest("GET", rm.apiURL+"/v1/rules", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+rm.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var rs RuleSet
	if err := json.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}

	rm.mu.RLock()
	currentVersion := rm.current.Version
	rm.mu.RUnlock()

	if rs.Version > currentVersion {
		log.Printf("bbloker: rules updated v%d → v%d", currentVersion, rs.Version)
		rm.applyRules(rs)
	}
}

// isBlockedUA does case-insensitive substring matching against all blocked UA patterns.
func (rm *ruleManager) isBlockedUA(ua string) bool {
	lower := strings.ToLower(ua)
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	for _, pattern := range rm.uaLower {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// isBlockedIP checks whether ip falls within any blocked CIDR range.
func (rm *ruleManager) isBlockedIP(ip string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	for _, cidr := range rm.current.BlockedIPs {
		if cidrContains(cidr, ip) {
			return true
		}
	}
	return false
}

// headerAnomalyScore sums the weights of header patterns whose regex matches.
func (rm *ruleManager) headerAnomalyScore(headers map[string]string) float64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var score float64
	for i, hp := range rm.current.HeaderPatterns {
		if rm.headerRe[i] == nil {
			continue
		}
		val := headers[hp.Name]
		if rm.headerRe[i].MatchString(val) {
			score += hp.Weight
		}
	}
	return score
}

func (rm *ruleManager) anomalyThreshold() float64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.current.AnomalyThreshold
}
