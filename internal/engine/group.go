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
	groups  map[string]*ManagedGroup
	portMap map[int]string
	logger  *slog.Logger
	mu      sync.RWMutex
}

// NewGroupManager constructs a GroupManager from config.
func NewGroupManager(groups []config.ProxyGroup, mappings []config.PortMapping, logger *slog.Logger) (*GroupManager, error) {
	gm := &GroupManager{
		groups:  make(map[string]*ManagedGroup),
		portMap: make(map[int]string),
		logger:  logger,
	}
	for i := range groups {
		g := &groups[i]
		ptrs := make([]*config.ProxyEntry, len(g.Proxies))
		for j := range g.Proxies {
			ptrs[j] = &g.Proxies[j]
		}
		ttl := time.Duration(g.StickyTTLSec) * time.Second
		rot, err := NewRotator(g.RotationMode, ptrs, RotatorOpts{StickyTTL: ttl, Logger: logger})
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
		if _, ok := gm.groups[m.GroupName]; !ok {
			return nil, fmt.Errorf("port mapping references unknown group: %s", m.GroupName)
		}
		for p := m.PortStart; p <= m.PortEnd; p++ {
			gm.portMap[p] = m.GroupName
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

// GetNextProxy picks the next proxy for a port/clientIP combination.
func (gm *GroupManager) GetNextProxy(port int, clientIP string) (*config.ProxyEntry, error) {
	g, err := gm.GetGroupForPort(port)
	if err != nil {
		return nil, err
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

// AllGroupProxies returns ProxyGroup snapshots suitable for passing to the
// HealthChecker.
func (gm *GroupManager) AllGroupProxies() []*config.ProxyGroup {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	out := make([]*config.ProxyGroup, 0, len(gm.groups))
	for name, g := range gm.groups {
		pg := &config.ProxyGroup{Name: name, RotationMode: g.Mode}
		pg.Proxies = make([]config.ProxyEntry, 0, len(g.Proxies))
		for _, p := range g.Proxies {
			pg.Proxies = append(pg.Proxies, *p)
		}
		out = append(out, pg)
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
	gm.mu.Unlock()
	g.Rotator.UpdateProxies(proxies)
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
