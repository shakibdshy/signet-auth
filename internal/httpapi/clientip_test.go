package httpapi

import (
	"net/netip"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	tests := []struct {
		name   string
		remote string
		xff    string
		trust  []netip.Prefix
		want   string
	}{
		{"no trust ignores xff", "203.0.113.9:1234", "198.51.100.2", nil, "203.0.113.9"},
		{"trusted uses untrusted hop", "127.0.0.1:1234", "198.51.100.7, 203.0.113.8", trusted, "203.0.113.8"},
		{"spoofed leftmost ignored", "127.0.0.1:1234", "1.1.1.1, 198.51.100.7, 203.0.113.8", trusted, "203.0.113.8"},
		{"ipv6 normalized", "127.0.0.1:1234", "2001:0db8:0000:0000:0000:0000:0000:0001", trusted, "2001:db8::1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveClientIP(tc.remote, tc.xff, tc.trust); got != tc.want {
				t.Fatalf("resolveClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
