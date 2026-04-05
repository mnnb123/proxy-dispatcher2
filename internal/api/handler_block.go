package api

import (
	"encoding/json"
	"net/http"
	"regexp"

	"proxy-dispatcher/internal/config"
)

func (s *Server) handleGetBlockDomains(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"default_action": s.cfg.DefaultBlockAction,
		"rules":          s.cfg.BlockDomains,
		"count":          len(s.cfg.BlockDomains),
	})
}

type postBlockDomainsReq struct {
	DefaultAction string              `json:"default_action"`
	RawText       string              `json:"raw_text"`
	Rules         []config.DomainRule `json:"rules"`
}

func (s *Server) handlePostBlockDomains(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postBlockDomainsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}

	if req.DefaultAction != "" {
		if req.DefaultAction != "403" && req.DefaultAction != "reset" && req.DefaultAction != "drop" {
			respondError(w, http.StatusBadRequest, "default_action must be 403, reset, or drop")
			return
		}
		s.cfg.DefaultBlockAction = req.DefaultAction
	}

	var rules []config.DomainRule
	if req.RawText != "" {
		rules = parseDomainText(req.RawText, "")
	} else if len(req.Rules) > 0 {
		rules = req.Rules
	}

	for _, rule := range rules {
		if rule.Type == "regex" || looksRegex(rule.Pattern) {
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				respondError(w, http.StatusBadRequest, "invalid regex: "+rule.Pattern)
				return
			}
		}
	}

	s.cfg.BlockDomains = rules
	if err := s.ruleEngine.Reload(s.cfg); err != nil {
		respondError(w, http.StatusBadRequest, "rule compile error: "+err.Error())
		return
	}
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]int{"count": len(rules)})
}
