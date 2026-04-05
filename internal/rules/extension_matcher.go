package rules

import (
	"strings"

	"proxy-dispatcher/internal/config"
)

// ExtensionMatcher matches URL paths by file extension.
type ExtensionMatcher struct {
	extMap map[string]string
}

// NewExtensionMatcher compiles ExtensionRules into an ExtensionMatcher.
func NewExtensionMatcher(rules []config.ExtensionRule, defaultAction string) *ExtensionMatcher {
	em := &ExtensionMatcher{extMap: make(map[string]string)}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		action := r.Action
		if action == "" {
			action = defaultAction
		}
		em.extMap[strings.ToLower(r.Extension)] = action
	}
	return em
}

// Match returns whether the URL path's extension matches a rule.
func (em *ExtensionMatcher) Match(urlPath string) (bool, string) {
	if idx := strings.Index(urlPath, "?"); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	if idx := strings.Index(urlPath, "#"); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	dot := strings.LastIndex(urlPath, ".")
	if dot < 0 || dot == len(urlPath)-1 {
		return false, ""
	}
	ext := strings.ToLower(urlPath[dot+1:])
	if action, ok := em.extMap[ext]; ok {
		return true, action
	}
	return false, ""
}
