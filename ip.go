package bbloker

import (
	"fmt"
	"net/http"
	"strings"
)

// extractIP reads the client IP from X-Forwarded-For, X-Real-IP, or
// RemoteAddr (in that order), stripping the port if present.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the comma-separated list is the client.
		ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		return stripPort(ip)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return stripPort(strings.TrimSpace(xri))
	}
	return stripPort(r.RemoteAddr)
}

func stripPort(addr string) string {
	// Handle [::1]:port style IPv6
	if idx := strings.LastIndex(addr, "]:"); idx != -1 {
		return addr[1:idx]
	}
	// Handle host:port — but only if there's exactly one colon (IPv4).
	if strings.Count(addr, ":") == 1 {
		host, _, _ := strings.Cut(addr, ":")
		return host
	}
	return addr
}

// cidrContains checks if ip falls within the given CIDR block.
// If cidr has no "/" it does an exact string match.
func cidrContains(cidr, ip string) bool {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return cidr == ip
	}

	cidrIP := ipToUint32(parts[0])
	targetIP := ipToUint32(ip)
	if cidrIP == 0 || targetIP == 0 {
		return false
	}

	var bits int
	fmt.Sscanf(parts[1], "%d", &bits)
	if bits < 0 || bits > 32 {
		return false
	}

	mask := uint32(0xFFFFFFFF) << (32 - bits)
	return (cidrIP & mask) == (targetIP & mask)
}

func ipToUint32(ip string) uint32 {
	parts := strings.SplitN(ip, ".", 4)
	if len(parts) != 4 {
		return 0
	}
	var result uint32
	for _, p := range parts {
		var octet int
		fmt.Sscanf(p, "%d", &octet)
		if octet < 0 || octet > 255 {
			return 0
		}
		result = result<<8 | uint32(octet)
	}
	return result
}
