package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"proxy-dispatcher/internal/config"
)

func (s *Server) handleGetBypassDomains(w http.ResponseWriter, r *http.Request) {
	enabledCount := 0
	for _, d := range s.cfg.BypassDomains {
		if d.Enabled {
			enabledCount++
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"default_action": s.cfg.DefaultBypassAction,
		"rules":          s.cfg.BypassDomains,
		"count":          len(s.cfg.BypassDomains),
		"enabled_count":  enabledCount,
	})
}

type postBypassDomainsReq struct {
	DefaultAction string              `json:"default_action"`
	RawText       string              `json:"raw_text"`
	Rules         []config.DomainRule `json:"rules"`
}

func (s *Server) handlePostBypassDomains(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postBypassDomainsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}

	if req.DefaultAction != "" {
		s.cfg.DefaultBypassAction = req.DefaultAction
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

	s.cfg.BypassDomains = rules
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

func (s *Server) handleGetBypassExtensions(w http.ResponseWriter, r *http.Request) {
	groups := make(map[string][]config.ExtensionRule)
	for _, ext := range s.cfg.BypassExtensions {
		groups[ext.Group] = append(groups[ext.Group], ext)
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"default_action": s.cfg.DefaultBypassAction,
		"groups":         groups,
	})
}

type postBypassExtReq struct {
	DefaultAction string                `json:"default_action"`
	Extensions    []config.ExtensionRule `json:"extensions"`
}

func (s *Server) handlePostBypassExtensions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postBypassExtReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.DefaultAction != "" {
		s.cfg.DefaultBypassAction = req.DefaultAction
	}
	s.cfg.BypassExtensions = req.Extensions
	if err := s.ruleEngine.Reload(s.cfg); err != nil {
		respondError(w, http.StatusBadRequest, "rule compile error: "+err.Error())
		return
	}
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetResourceProxy(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ResourceProxy == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{"configured": false})
		return
	}
	p := s.cfg.ResourceProxy
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"configured": true,
		"host":       p.Host,
		"port":       p.Port,
		"type":       p.Type,
		"user":       p.User,
	})
}

type postResourceProxyReq struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Type string `json:"type"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (s *Server) handlePostResourceProxy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req postResourceProxyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Host == "" {
		s.cfg.ResourceProxy = nil
	} else {
		if req.Type != "http" && req.Type != "socks5" {
			respondError(w, http.StatusBadRequest, "type must be http or socks5")
			return
		}
		s.cfg.ResourceProxy = &config.ProxyEntry{
			Host: req.Host, Port: req.Port, Type: req.Type,
			User: req.User, Pass: req.Pass, Status: "unknown",
		}
	}
	if err := config.SaveConfig(s.cfgPath, s.cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "save failed")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func parseDomainText(raw string, defaultAction string) []config.DomainRule {
	var rules []config.DomainRule
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rules = append(rules, config.DomainRule{
			Pattern: line,
			Enabled: true,
			Action:  defaultAction,
		})
	}
	return rules
}

func looksRegex(s string) bool {
	for _, ch := range []byte{'[', ']', '+', '\\', '^', '$', '|', '{'} {
		if strings.ContainsRune(s, rune(ch)) {
			return true
		}
	}
	return strings.Contains(s, ".*") || strings.HasPrefix(s, "(?")
}
