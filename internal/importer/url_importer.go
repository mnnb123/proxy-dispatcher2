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
	sources    []config.ImportSource // guarded by srcMu
	srcMu      sync.Mutex
	groupMgr   *engine.GroupManager
	httpClient *http.Client
	stopCh     chan struct{}
	logger     *slog.Logger
	mu         sync.Mutex // serialises MergeIntoGroup
}

// NewURLImporter constructs an importer from config sources. The slice is
// copied: the importer owns its runtime view (LastFetch/LastCount).
func NewURLImporter(sources []config.ImportSource, groupMgr *engine.GroupManager, logger *slog.Logger) *URLImporter {
	own := make([]config.ImportSource, len(sources))
	copy(own, sources)
	return &URLImporter{
		sources:    own,
		groupMgr:   groupMgr,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		stopCh:     make(chan struct{}),
		logger:     logger,
	}
}

// Start launches a goroutine per enabled source.
func (ui *URLImporter) Start() {
	ui.srcMu.Lock()
	defer ui.srcMu.Unlock()
	for _, s := range ui.sources {
		if !s.Enabled {
			continue
		}
		go ui.fetchLoop(s.Name, s.IntervalSec)
	}
}

// fetchLoop refetches the named source on its interval. It works by name so
// results are recorded on the shared entry, not on a private copy.
func (ui *URLImporter) fetchLoop(name string, intervalSec int) {
	if intervalSec <= 0 {
		intervalSec = 300
	}
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()
	if _, err := ui.FetchNow(name); err != nil {
		ui.logger.Warn("initial fetch failed", "source", name, "error", err)
	}
	for {
		select {
		case <-ui.stopCh:
			return
		case <-ticker.C:
			if _, err := ui.FetchNow(name); err != nil {
				ui.logger.Warn("fetch failed", "source", name, "error", err)
			}
		}
	}
}

// fetchOne downloads and merges one source. It takes the source by value
// (a snapshot) and performs no locking around the network call.
func (ui *URLImporter) fetchOne(source config.ImportSource) (int, error) {
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

	// Snapshot taken under the GroupManager's lock (reading
	// ManagedGroup.Proxies directly raced with UpdateGroupProxies/Reload).
	current, ok := ui.groupMgr.GroupProxies()[groupName]
	if !ok {
		return fmt.Errorf("unknown group: %s", groupName)
	}

	key := func(p *config.ProxyEntry) string { return fmt.Sprintf("%s:%d", p.Host, p.Port) }
	incoming := make(map[string]*config.ProxyEntry, len(newProxies))
	for i := range newProxies {
		incoming[key(&newProxies[i])] = &newProxies[i]
	}

	merged := make([]*config.ProxyEntry, 0, len(current)+len(newProxies))
	seen := make(map[string]bool, len(current))
	// Keep existing proxies (and therefore their ports), updating auth if
	// the new list carries credentials.
	for _, oldP := range current {
		k := key(oldP)
		seen[k] = true
		if np, ok := incoming[k]; ok && np.User != "" {
			oldP.User = np.User
			oldP.Pass = np.Pass
		}
		merged = append(merged, oldP)
	}
	// Add brand-new proxies at the end.
	for i := range newProxies {
		np := newProxies[i]
		k := key(&np)
		if seen[k] {
			continue
		}
		seen[k] = true
		if np.Status == "" {
			np.Status = "unknown"
		}
		p := np
		merged = append(merged, &p)
	}
	return ui.groupMgr.UpdateGroupProxies(groupName, merged)
}

// FetchNow triggers an immediate fetch for the named source and records
// LastFetch/LastCount on it.
func (ui *URLImporter) FetchNow(sourceName string) (int, error) {
	ui.srcMu.Lock()
	var snap config.ImportSource
	found := false
	for i := range ui.sources {
		if ui.sources[i].Name == sourceName {
			snap = ui.sources[i]
			found = true
			break
		}
	}
	ui.srcMu.Unlock()
	if !found {
		return 0, fmt.Errorf("source not found: %s", sourceName)
	}

	n, err := ui.fetchOne(snap)

	if n > 0 {
		ui.srcMu.Lock()
		for i := range ui.sources {
			if ui.sources[i].Name == sourceName {
				ui.sources[i].LastFetch = time.Now().Unix()
				ui.sources[i].LastCount = n
				break
			}
		}
		ui.srcMu.Unlock()
	}
	return n, err
}

// Sources returns a copy of the current source list.
func (ui *URLImporter) Sources() []config.ImportSource {
	ui.srcMu.Lock()
	defer ui.srcMu.Unlock()
	out := make([]config.ImportSource, len(ui.sources))
	copy(out, ui.sources)
	return out
}

// Stop halts all fetch loops.
func (ui *URLImporter) Stop() {
	select {
	case <-ui.stopCh:
	default:
		close(ui.stopCh)
	}
}
