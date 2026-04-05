package rules

import "proxy-dispatcher/internal/config"

// DomainMatcher matches hostnames against bypass domain rules.
type DomainMatcher struct {
	base *baseMatcher
}

// NewDomainMatcher compiles DomainRules into a DomainMatcher.
func NewDomainMatcher(rules []config.DomainRule, defaultAction string) (*DomainMatcher, error) {
	base, err := newBaseMatcher(rules, defaultAction)
	if err != nil {
		return nil, err
	}
	return &DomainMatcher{base: base}, nil
}

// Match returns whether target matches any bypass rule and the action.
func (dm *DomainMatcher) Match(target string) (bool, string) {
	return dm.base.match(target)
}
