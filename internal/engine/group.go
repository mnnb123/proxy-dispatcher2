package engine

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"proxy-dispatcher/internal/config"
)

// ManagedGroup is a runtime view of a proxy group with its rotator attached.
type ManagedGroup struct {
	Name    string
	Proxies []*config.ProxyEntry
	Rotator Rotator
	Mode    string
}

// GroupManager maps inbound ports to proxy groups.
type GroupManager struct {
	groups       map[string]*ManagedGroup
	portMap      map[int]string
	portProxyMap map[int]*config.ProxyEntry // direct port→proxy 1:1 lookup
	mappings     []config.PortMapping
	logger       *slog.Logger
	mu           sync.RWMutex
}

// assigned drops placeholder entries (ports with no proxy): they keep their
// position for the port mapping but must never be handed out by a rotator.
func assigned(ptrs []*config.ProxyEntry) []*config.ProxyEntry {
	out := make([]*config.ProxyEntry, 0, len(ptrs))
	for _, p := range ptrs {
		if p != nil && !p.IsEmpty() {
			out = append(out, p)
		}
	}
	return out
}

// NewGroupManager constructs a GroupManager from config.
func NewGroupManager(groups []config.ProxyGroup, mappings []config.PortMapping, logger *slog.Logger) (*GroupManager, error) {
	gm := &GroupManager{
		groups:       make(map[string]*ManagedGroup),
		portMap:      make(map[int]string),
		portProxyMap: make(map[int]*config.ProxyEntry),
		mappings:     append([]config.PortMapping(nil), mappings...),
		logger:       logger,
	}
	for i := range groups {
		g := &groups[i]
		ptrs := make([]*config.ProxyEntry, len(g.Proxies))
		for j := range g.Proxies {
			ptrs[j] = &g.Proxies[j]
		}
		ttl := time.Duration(g.StickyTTLSec) * time.Second
		rot, err := NewRotator(g.RotationMode, assigned(ptrs), RotatorOpts{StickyTTL: ttl, Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		gm.groups[g.Name] = &ManagedGroup{
			Name:    g.Name,
			Proxies: ptrs,
			Rotator: rot,
			Mode:    g.RotationMode,
		}
	}
	for _, m := range mappings {
		g, ok := gm.groups[m.GroupName]
		if !ok {
			logger.Warn("port mapping references unknown group, skipping", "group", m.GroupName)
			continue
		}
		for p := m.PortStart; p <= m.PortEnd; p++ {
			gm.portMap[p] = m.GroupName
			// Build 1:1 port→proxy map by index.
			idx := p - m.PortStart
			if idx >= 0 && idx < len(g.Proxies) {
				gm.portProxyMap[p] = g.Proxies[idx]
				// Debug, not Info: with thousands of ports this line flooded
				// the log on every reload.
				logger.Debug("port→proxy mapped", "port", p, "proxy", fmt.Sprintf("%s:%d", g.Proxies[idx].Host, g.Proxies[idx].Port), "idx", idx)
			}
		}
	}
	return gm, nil
}

// GetGroupForPort returns the ManagedGroup bound to the given port,
// falling back to the "default" group if one exists.
func (gm *GroupManager) GetGroupForPort(port int) (*ManagedGroup, error) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	name, ok := gm.portMap[port]
	if !ok {
		if g, ok := gm.groups["default"]; ok {
			return g, nil
		}
		return nil, fmt.Errorf("no group for port %d", port)
	}
	g, ok := gm.groups[name]
	if !ok {
		return nil, fmt.Errorf("group %q missing", name)
	}
	return g, nil
}

// GetProxyForPort returns the proxy directly mapped to this port (1:1).
// This is the primary lookup — no rotation involved.
func (gm *GroupManager) GetProxyForPort(port int) (*config.ProxyEntry, bool) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	p, ok := gm.portProxyMap[port]
	return p, ok
}

// GetNextProxy picks the next proxy for a port/clientIP combination.
// Falls back to rotator only if no direct 1:1 mapping exists.
func (gm *GroupManager) GetNextProxy(port int, clientIP string) (*config.ProxyEntry, error) {
	// Always try direct 1:1 mapping first.
	if p, ok := gm.GetProxyForPort(port); ok {
		if p.IsEmpty() {
			// The port sits in an assigned position that has no proxy:
			// never fall back to another port's proxy.
			return nil, fmt.Errorf("no proxy assigned to port %d", port)
		}
		return p, nil
	}
	g, err := gm.GetGroupForPort(port)
	if err != nil {
		return nil, err
	}
	return g.Rotator.Next(clientIP)
}

// NextProxy selects a proxy for the given port.
// Uses direct 1:1 lookup. Falls back to rotator only if no mapping.
func (g *ManagedGroup) NextProxy(port int, clientIP string, gm *GroupManager) (*config.ProxyEntry, error) {
	if p, ok := gm.GetProxyForPort(port); ok {
		if p.IsEmpty() {
			return nil, fmt.Errorf("no proxy assigned to port %d", port)
		}
		return p, nil
	}
	return g.Rotator.Next(clientIP)
}

// AllGroups returns the runtime managed groups.
func (gm *GroupManager) AllGroups() []*ManagedGroup {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	out := make([]*ManagedGroup, 0, len(gm.groups))
	for _, g := range gm.groups {
		out = append(out, g)
	}
	return out
}

// GroupProxies returns a snapshot of the live proxy pointers for every
// group, keyed by group name. Callers that need to observe or update
// per-proxy runtime state (health status, latency, weight) must go through
// these pointers — copying the entries would detach them from routing.
func (gm *GroupManager) GroupProxies() map[string][]*config.ProxyEntry {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	out := make(map[string][]*config.ProxyEntry, len(gm.groups))
	for name, g := range gm.groups {
		ptrs := make([]*config.ProxyEntry, len(g.Proxies))
		copy(ptrs, g.Proxies)
		out[name] = ptrs
	}
	return out
}

// Reload validates new groups/mappings then atomically swaps.
func (gm *GroupManager) Reload(groups []config.ProxyGroup, mappings []config.PortMapping) error {
	newGm, err := NewGroupManager(groups, mappings, gm.logger)
	if err != nil {
		return err
	}
	gm.mu.Lock()
	gm.groups = newGm.groups
	gm.portMap = newGm.portMap
	gm.portProxyMap = newGm.portProxyMap
	gm.mappings = newGm.mappings
	gm.mu.Unlock()
	return nil
}

// UpdateGroupProxies updates a single group's proxy list in place.
func (gm *GroupManager) UpdateGroupProxies(groupName string, proxies []*config.ProxyEntry) error {
	gm.mu.Lock()
	g, ok := gm.groups[groupName]
	if !ok {
		gm.mu.Unlock()
		return fmt.Errorf("unknown group: %s", groupName)
	}
	g.Proxies = proxies
	// Rebuild this group's 1:1 port→proxy bindings: proxies appended by an
	// import previously never received a port until the next full reload.
	for _, m := range gm.mappings {
		if m.GroupName != groupName {
			continue
		}
		for p := m.PortStart; p <= m.PortEnd; p++ {
			if idx := p - m.PortStart; idx < len(proxies) {
				gm.portProxyMap[p] = proxies[idx]
			} else {
				delete(gm.portProxyMap, p)
			}
		}
	}
	gm.mu.Unlock()
	g.Rotator.UpdateProxies(assigned(proxies))
	return nil
}

// AllPorts returns every port in every mapping (useful for listener startup).
func (gm *GroupManager) AllPorts() []int {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	out := make([]int, 0, len(gm.portMap))
	for p := range gm.portMap {
		out = append(out, p)
	}
	return out
}
