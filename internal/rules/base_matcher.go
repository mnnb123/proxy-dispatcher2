// Package rules implements domain/extension/block matching for routing decisions.
package rules

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"proxy-dispatcher/internal/config"
)

type wildcardEntry struct {
	Suffix string
	Action string
}

type regexpEntry struct {
	Pattern *regexp.Regexp
	Action  string
}

type cidrEntry struct {
	Network *net.IPNet
	Action  string
}

type baseMatcher struct {
	exactMap  map[string]string
	wildcards []wildcardEntry
	regexps   []regexpEntry
	cidrNets  []cidrEntry
}

func newBaseMatcher(rules []config.DomainRule, defaultAction string) (*baseMatcher, error) {
	bm := &baseMatcher{
		exactMap: make(map[string]string),
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		action := r.Action
		if action == "" {
			action = defaultAction
		}
		pattern := strings.TrimSpace(r.Pattern)
		if pattern == "" {
			continue
		}

		ruleType := r.Type
		if ruleType == "" {
			ruleType = detectType(pattern)
		}

		switch ruleType {
		case "cidr":
			_, ipnet, err := net.ParseCIDR(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", pattern, err)
			}
			bm.cidrNets = append(bm.cidrNets, cidrEntry{Network: ipnet, Action: action})
		case "regex":
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
			}
			bm.regexps = append(bm.regexps, regexpEntry{Pattern: re, Action: action})
		case "wildcard":
			suffix := strings.ToLower(strings.TrimPrefix(pattern, "*"))
			bm.wildcards = append(bm.wildcards, wildcardEntry{Suffix: suffix, Action: action})
		case "ip":
			bm.exactMap[strings.ToLower(pattern)] = action
		default: // "exact" or unrecognized
			bm.exactMap[strings.ToLower(pattern)] = action
		}
	}
	return bm, nil
}

func detectType(pattern string) string {
	if strings.Contains(pattern, "/") {
		if _, _, err := net.ParseCIDR(pattern); err == nil {
			return "cidr"
		}
	}
	if strings.HasPrefix(pattern, "*.") {
		return "wildcard"
	}
	if looksLikeRegex(pattern) {
		return "regex"
	}
	if net.ParseIP(pattern) != nil {
		return "ip"
	}
	return "exact"
}

func looksLikeRegex(s string) bool {
	if strings.HasPrefix(s, "(?") {
		return true
	}
	for _, ch := range []byte{'[', ']', '+', '\\', '^', '$', '|', '{'} {
		if strings.ContainsRune(s, rune(ch)) {
			return true
		}
	}
	if strings.Contains(s, ".*") {
		return true
	}
	return false
}

func (bm *baseMatcher) match(target string) (bool, string) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false, ""
	}

	// Strip port if present.
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	if action, ok := bm.exactMap[host]; ok {
		return true, action
	}

	for _, w := range bm.wildcards {
		// *.google.com matches sub.google.com and google.com itself.
		if strings.HasSuffix(host, w.Suffix) || host == strings.TrimPrefix(w.Suffix, ".") {
			return true, w.Action
		}
	}

	for _, re := range bm.regexps {
		if re.Pattern.MatchString(host) {
			return true, re.Action
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, c := range bm.cidrNets {
			if c.Network.Contains(ip) {
				return true, c.Action
			}
		}
	}

	return false, ""
}
