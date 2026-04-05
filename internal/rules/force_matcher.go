package rules

import "proxy-dispatcher/internal/config"

// ForceMatcher matches hostnames against force-proxy domain rules.
type ForceMatcher struct {
	base *baseMatcher
}

// NewForceMatcher compiles DomainRules into a ForceMatcher.
func NewForceMatcher(rules []config.DomainRule) (*ForceMatcher, error) {
	base, err := newBaseMatcher(rules, "proxy")
	if err != nil {
		return nil, err
	}
	return &ForceMatcher{base: base}, nil
}

// Match returns whether target matches any force-proxy rule.
func (fm *ForceMatcher) Match(target string) bool {
	matched, _ := fm.base.match(target)
	return matched
}
