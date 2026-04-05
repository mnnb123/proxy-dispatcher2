package rules

import (
	"log/slog"
	"sync"

	"proxy-dispatcher/internal/config"
)

// BlockInfo describes how to block a connection.
type BlockInfo struct {
	Action string
	Reason string
}

// RouteAction is the result of evaluating a target against all rules.
type RouteAction struct {
	Type  string // "proxy", "direct", "resource", "block"
	Block BlockInfo
}

// RuleEngine evaluates targets against bypass, extension, block, and
// force-proxy rules.
type RuleEngine struct {
	domainMatcher    *DomainMatcher
	extensionMatcher *ExtensionMatcher
	blockMatcher     *BlockMatcher
	forceMatcher     *ForceMatcher
	defaultBypass    string
	defaultBlock     string
	logger           *slog.Logger
	mu               sync.RWMutex
}

// NewRuleEngine compiles all rules from cfg into a RuleEngine.
func NewRuleEngine(cfg *config.AppConfig, logger *slog.Logger) (*RuleEngine, error) {
	dm, err := NewDomainMatcher(cfg.BypassDomains, cfg.DefaultBypassAction)
	if err != nil {
		return nil, err
	}
	em := NewExtensionMatcher(cfg.BypassExtensions, cfg.DefaultBypassAction)
	bm, err := NewBlockMatcher(cfg.BlockDomains, cfg.DefaultBlockAction)
	if err != nil {
		return nil, err
	}
	fm, err := NewForceMatcher(cfg.ForceProxyDomains)
	if err != nil {
		return nil, err
	}
	return &RuleEngine{
		domainMatcher:    dm,
		extensionMatcher: em,
		blockMatcher:     bm,
		forceMatcher:     fm,
		defaultBypass:    cfg.DefaultBypassAction,
		defaultBlock:     cfg.DefaultBlockAction,
		logger:           logger,
	}, nil
}

// Evaluate checks target+urlPath against block, bypass domain, bypass
// extension rules in order. Returns the first matching RouteAction.
func (re *RuleEngine) Evaluate(target string, urlPath string) RouteAction {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if matched, action, reason := re.blockMatcher.Match(target); matched {
		return RouteAction{Type: "block", Block: BlockInfo{Action: action, Reason: reason}}
	}
	if matched, action := re.domainMatcher.Match(target); matched {
		return RouteAction{Type: action}
	}
	if matched, action := re.extensionMatcher.Match(urlPath); matched {
		return RouteAction{Type: action}
	}
	return RouteAction{Type: "proxy"}
}

// Reload recompiles all rules from cfg. On failure the old matchers are kept.
func (re *RuleEngine) Reload(cfg *config.AppConfig) error {
	dm, err := NewDomainMatcher(cfg.BypassDomains, cfg.DefaultBypassAction)
	if err != nil {
		return err
	}
	em := NewExtensionMatcher(cfg.BypassExtensions, cfg.DefaultBypassAction)
	bm, err := NewBlockMatcher(cfg.BlockDomains, cfg.DefaultBlockAction)
	if err != nil {
		return err
	}

	fm, err := NewForceMatcher(cfg.ForceProxyDomains)
	if err != nil {
		return err
	}

	re.mu.Lock()
	re.domainMatcher = dm
	re.extensionMatcher = em
	re.blockMatcher = bm
	re.forceMatcher = fm
	re.defaultBypass = cfg.DefaultBypassAction
	re.defaultBlock = cfg.DefaultBlockAction
	re.mu.Unlock()
	return nil
}

// IsForceProxy returns whether target must always use proxy rotation.
func (re *RuleEngine) IsForceProxy(target string) bool {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return re.forceMatcher.Match(target)
}
