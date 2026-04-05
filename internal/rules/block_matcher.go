package rules

import (
	"fmt"

	"proxy-dispatcher/internal/config"
)

// BlockMatcher matches hostnames against block domain rules.
type BlockMatcher struct {
	base *baseMatcher
}

// NewBlockMatcher compiles DomainRules into a BlockMatcher.
func NewBlockMatcher(rules []config.DomainRule, defaultAction string) (*BlockMatcher, error) {
	base, err := newBaseMatcher(rules, defaultAction)
	if err != nil {
		return nil, err
	}
	return &BlockMatcher{base: base}, nil
}

// Match returns whether target is blocked, the block action, and a reason.
func (bm *BlockMatcher) Match(target string) (bool, string, string) {
	matched, action := bm.base.match(target)
	if !matched {
		return false, "", ""
	}
	reason := fmt.Sprintf("blocked: %s", target)
	return true, action, reason
}
