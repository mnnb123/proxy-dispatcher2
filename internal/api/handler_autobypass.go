package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"proxy-dispatcher/internal/config"
)

func (s *Server) handleGetAutoBypass(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.cfg.AutoBypass)
}

func (s *Server) handleAutoBypassStats(w http.ResponseWriter, r *http.Request) {
	if s.sizeForwarder == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{"events": []struct{}{}, "total": 0})
		return
	}
	events, total := s.sizeForwarder.BypassStats()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  total,
	})
}

func (s *Server) handlePostAutoBypass(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req config.AutoBypassConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	s.cfg.AutoBypass = req
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetForceProxy(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"rules": s.cfg.ForceProxyDomains,
		"count": len(s.cfg.ForceProxyDomains),
	})
}

type postForceProxyReq struct {
	RawText string              `json:"raw_text"`
	Rules   []config.DomainRule `json:"rules"`
}

func (s *Server) handlePostForceProxy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postForceProxyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}

	var rules []config.DomainRule
	if req.RawText != "" {
		for _, line := range strings.Split(req.RawText, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rules = append(rules, config.DomainRule{Pattern: line, Enabled: true})
		}
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

	s.cfg.ForceProxyDomains = rules
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
