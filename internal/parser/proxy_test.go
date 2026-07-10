package parser

import "testing"

func TestParseProxyList(t *testing.T) {
	tests := []struct {
		name string
		line string
		host string
		port int
		user string
		pass string
		typ  string
		fail bool
	}{
		{name: "host:port", line: "1.2.3.4:8080", host: "1.2.3.4", port: 8080, typ: "http"},
		{name: "host:port:user:pass", line: "1.2.3.4:8080:alice:secret", host: "1.2.3.4", port: 8080, user: "alice", pass: "secret", typ: "http"},
		{name: "user:pass@host:port", line: "alice:secret@1.2.3.4:8080", host: "1.2.3.4", port: 8080, user: "alice", pass: "secret", typ: "http"},
		{name: "scheme with @", line: "socks5://alice:secret@1.2.3.4:1080", host: "1.2.3.4", port: 1080, user: "alice", pass: "secret", typ: "socks5"},
		{name: "pass containing @", line: "alice:s@cret@1.2.3.4:8080", host: "1.2.3.4", port: 8080, user: "alice", pass: "s@cret", typ: "http"},
		{name: "pass containing colon", line: "alice:se:cret@1.2.3.4:8080", host: "1.2.3.4", port: 8080, user: "alice", pass: "se:cret", typ: "http"},
		{name: "missing pass before @", line: "alice@1.2.3.4:8080", fail: true},
		{name: "missing port after @", line: "alice:secret@1.2.3.4", fail: true},
		{name: "bad port", line: "alice:secret@1.2.3.4:abc", fail: true},
		{name: "port out of range", line: "1.2.3.4:99999", fail: true},
		{name: "three parts", line: "1.2.3.4:8080:alice", fail: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, errs := ParseProxyList(tt.line, "http")
			if tt.fail {
				if len(errs) != 1 || len(entries) != 0 {
					t.Fatalf("expected parse error, got entries=%v errs=%v", entries, errs)
				}
				return
			}
			if len(errs) != 0 || len(entries) != 1 {
				t.Fatalf("expected 1 entry, got entries=%v errs=%v", entries, errs)
			}
			e := entries[0]
			if e.Host != tt.host || e.Port != tt.port || e.User != tt.user || e.Pass != tt.pass || e.Type != tt.typ {
				t.Fatalf("got %+v, want host=%s port=%d user=%s pass=%s type=%s", e, tt.host, tt.port, tt.user, tt.pass, tt.typ)
			}
		})
	}
}

func TestParseProxyListMultiline(t *testing.T) {
	raw := "1.2.3.4:8080\n\nalice:secret@5.6.7.8:1080\nbad-line\n"
	entries, errs := ParseProxyList(raw, "http")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %v", entries)
	}
	if len(errs) != 1 || errs[0].Line != 4 {
		t.Fatalf("expected 1 error on line 4, got %v", errs)
	}
}
