package api

import (
	"fmt"
	"sort"
	"testing"
)

func TestParseIPList(t *testing.T) {
	cases := map[string]string{
		`{"ok":true,"count":3,"ips":["1.1.1.1"," 2.2.2.2 ","bad"],"leads":[{"ip":"9.9.9.9","cc":"US"}]}`: "[1.1.1.1 2.2.2.2]",
		`{"leads":[{"ip":"9.9.9.9"},{"ip":"8.8.8.8"}]}`:                                                  "[8.8.8.8 9.9.9.9]",
		`["3.3.3.3","4.4.4.4","3.3.3.3"]`:                                                                "[3.3.3.3 4.4.4.4]",
		"5.5.5.5\r\n6.6.6.6, 7.7.7.7\nnot-an-ip\n":                                                       "[5.5.5.5 6.6.6.6 7.7.7.7]",
		"": "[]",
	}
	for in, want := range cases {
		var got []string
		for ip := range parseIPList([]byte(in)) {
			got = append(got, ip)
		}
		sort.Strings(got)
		if fmt.Sprint(got) != want {
			t.Errorf("parseIPList(%q) = %v, want %s", in, got, want)
		}
	}
}
