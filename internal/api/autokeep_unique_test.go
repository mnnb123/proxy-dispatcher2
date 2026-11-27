package api

import (
	"path/filepath"
	"testing"

	"proxy-dispatcher/internal/config"
)

// TestKnownIPsHistory: auto-keep (history=false) only avoids IPs the group
// holds now; manual fetch and the customer API (history=true) also avoid
// every IP in the group's history.
func TestKnownIPsHistory(t *testing.T) {
	s := &Server{
		cfgPath: filepath.Join(t.TempDir(), "config.json"),
		cfg: &config.AppConfig{ProxyGroups: []config.ProxyGroup{{
			Name:    "g",
			Proxies: []config.ProxyEntry{{Host: "10.0.0.1", Port: 1, Type: "socks5", ExternalIP: "1.1.1.1"}},
		}}},
	}
	if err := s.saveHistory("g", histFile{Snapshots: []histSnapshot{{
		ID: "a", Reason: "auto", Proxies: []histProxy{{Host: "10.0.0.2", Port: 1, ExternalIP: "2.2.2.2"}},
	}}}); err != nil {
		t.Fatal(err)
	}
	now := s.knownIPs("g", false)
	if !now["1.1.1.1"] || now["2.2.2.2"] || len(now) != 1 {
		t.Fatalf("current only: %v", now)
	}
	all := s.knownIPs("g", true)
	if !all["1.1.1.1"] || !all["2.2.2.2"] || len(all) != 2 {
		t.Fatalf("with history: %v", all)
	}
}
