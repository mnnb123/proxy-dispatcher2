package netutil

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestIPv4Target(t *testing.T) {
	calls := 0
	lookupIPv4 = func(ctx context.Context, host string) ([]net.IP, error) {
		calls++
		if host == "dual.example" {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return nil, errors.New("no A record")
	}
	ctx := context.Background()
	cases := map[string]string{
		"dual.example:443":   "93.184.216.34:443",
		"v6only.example:443": "v6only.example:443",
		"1.2.3.4:80":         "1.2.3.4:80",
		"[2001:db8::1]:80":   "[2001:db8::1]:80",
		"no-port":            "no-port",
	}
	for in, want := range cases {
		if got := IPv4Target(ctx, in); got != want {
			t.Errorf("IPv4Target(%q) = %q, want %q", in, got, want)
		}
	}
	before := calls
	IPv4Target(ctx, "dual.example:80")
	IPv4Target(ctx, "v6only.example:80")
	if calls != before {
		t.Errorf("answers were not cached: %d extra lookups", calls-before)
	}
}
