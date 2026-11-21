package httpapi

import (
	"net"
	"net/netip"
	"strings"
)

// resolveClientIP derives the rate-limit client address. X-Forwarded-For is
// used only when the immediate peer is an explicitly trusted proxy; the chain
// is walked right-to-left to the first untrusted hop.
func resolveClientIP(remoteAddr, xff string, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !isTrusted(peer, trusted) {
		return normalizeIP(host)
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(hops[i])
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !isTrusted(addr, trusted) {
			return normalizeIP(candidate)
		}
	}
	return normalizeIP(host)
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeIP(value string) string {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap().String()
	}
	return value
}
