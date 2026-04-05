// Package importer periodically fetches proxy lists from remote URLs.
package importer

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
	"proxy-dispatcher/internal/engine"
	"proxy-dispatcher/internal/parser"
)

const maxBodySize = 1 << 20 // 1MB

// URLImporter fetches ImportSource entries on their configured intervals.
type URLImporter struct {
	sources    []config.ImportSource
	groupMgr   *engine.GroupManager
	httpClient *http.Client
	stopCh     chan struct{}
	logger     *slog.Logger
	mu         sync.Mutex
}

// NewURLImporter constructs an importer from config sources.
func NewURLImporter(sources []config.ImportSource, groupMgr *engine.GroupManager, logger *slog.Logger) *URLImporter {
	return &URLImporter{
		sources:    sources,
		groupMgr:   groupMgr,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		stopCh:     make(chan struct{}),
		logger:     logger,
	}
}

// Start launches a goroutine per enabled source.
func (ui *URLImporter) Start() {
	for _, s := range ui.sources {
		if !s.Enabled {
			continue
		}
		go ui.fetchLoop(s)
	}
}

func (ui *URLImporter) fetchLoop(source config.ImportSource) {
	iv := source.IntervalSec
	if iv <= 0 {
		iv = 300
	}
	ticker := time.NewTicker(time.Duration(iv) * time.Second)
	defer ticker.Stop()
	if _, err := ui.fetchOne(&source); err != nil {
		ui.logger.Warn("initial fetch failed", "source", source.Name, "error", err)
	}
	for {
		select {
		case <-ui.stopCh:
			return
		case <-ticker.C:
			if _, err := ui.fetchOne(&source); err != nil {
				ui.logger.Warn("fetch failed", "source", source.Name, "error", err)
			}
		}
	}
}

func (ui *URLImporter) fetchOne(source *config.ImportSource) (int, error) {
	req, err := http.NewRequest("GET", source.URL, nil)
	if err != nil {
		return 0, err
	}
	if source.AuthHeader != "" {
		if i := strings.Index(source.AuthHeader, ":"); i > 0 {
			req.Header.Set(strings.TrimSpace(source.AuthHeader[:i]), strings.TrimSpace(source.AuthHeader[i+1:]))
		}
	}
	resp, err := ui.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return 0, err
	}
	ptype := source.ProxyType
	if ptype == "" {
		ptype = "http"
	}
	entries, _ := parser.ParseProxyList(string(body), ptype)
	if len(entries) == 0 {
		return 0, fmt.Errorf("no proxies parsed")
	}
	source.LastFetch = time.Now().Unix()
	source.LastCount = len(entries)
	if err := ui.MergeIntoGroup(source.GroupName, entries); err != nil {
		return len(entries), err
	}
	return len(entries), nil
}

// MergeIntoGroup merges new proxies into an existing group without dropping
// proxies not present in the new list.
func (ui *URLImporter) MergeIntoGroup(groupName string, newProxies []config.ProxyEntry) error {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	groups := ui.groupMgr.AllGroups()
	var target *engine.ManagedGroup
	for _, g := range groups {
		if g.Name == groupName {
			target = g
			break
		}
	}
	if target == nil {
		return fmt.Errorf("unknown group: %s", groupName)
	}

	key := func(p *config.ProxyEntry) string { return fmt.Sprintf("%s:%d", p.Host, p.Port) }
	existing := make(map[string]*config.ProxyEntry)
	for _, p := range target.Proxies {
		existing[key(p)] = p
	}

	merged := make([]*config.ProxyEntry, 0, len(target.Proxies)+len(newProxies))
	seen := make(map[string]bool)
	// Keep existing proxies, updating auth if new has auth.
	for _, oldP := range target.Proxies {
		k := key(oldP)
		seen[k] = true
		for i := range newProxies {
			np := &newProxies[i]
			if key(np) == k {
				if np.User != "" {
					oldP.User = np.User
					oldP.Pass = np.Pass
				}
				break
			}
		}
		merged = append(merged, oldP)
	}
	// Add brand-new proxies.
	for i := range newProxies {
		np := newProxies[i]
		if seen[key(&np)] {
			continue
		}
		if np.Status == "" {
			np.Status = "unknown"
		}
		p := np
		merged = append(merged, &p)
	}
	return ui.groupMgr.UpdateGroupProxies(groupName, merged)
}

// FetchNow triggers an immediate fetch for the named source.
func (ui *URLImporter) FetchNow(sourceName string) (int, error) {
	for i := range ui.sources {
		if ui.sources[i].Name == sourceName {
			return ui.fetchOne(&ui.sources[i])
		}
	}
	return 0, fmt.Errorf("source not found: %s", sourceName)
}

// Sources returns the current source list.
func (ui *URLImporter) Sources() []config.ImportSource {
	return ui.sources
}

// Stop halts all fetch loops.
func (ui *URLImporter) Stop() {
	select {
	case <-ui.stopCh:
	default:
		close(ui.stopCh)
	}
}
