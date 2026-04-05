package engine

import (
	"log/slog"
	"math/rand"
	"sort"
	"sync"

	"proxy-dispatcher/internal/config"
)

// WeightedRotator picks proxies proportionally to their Weight field.
type WeightedRotator struct {
	proxies     []*config.ProxyEntry
	aliveSubset []*config.ProxyEntry
	cumWeights  []int
	totalWeight int
	mu          sync.RWMutex
	rng         *rand.Rand
	rngMu       sync.Mutex
	logger      *slog.Logger
}

// Next returns a weighted-random alive proxy.
func (wr *WeightedRotator) Next(_ string) (*config.ProxyEntry, error) {
	wr.mu.RLock()
	total := wr.totalWeight
	cum := wr.cumWeights
	subset := wr.aliveSubset
	wr.mu.RUnlock()
	if total <= 0 || len(cum) == 0 {
		// Fallback: any alive.
		wr.mu.RLock()
		alive := getAlive(wr.proxies)
		wr.mu.RUnlock()
		if len(alive) == 0 {
			return nil, ErrNoProxyAvailable
		}
		wr.rngMu.Lock()
		idx := wr.rng.Intn(len(alive))
		wr.rngMu.Unlock()
		return alive[idx], nil
	}
	wr.rngMu.Lock()
	pick := wr.rng.Intn(total)
	wr.rngMu.Unlock()
	idx := sort.SearchInts(cum, pick+1)
	if idx >= len(subset) {
		idx = len(subset) - 1
	}
	return subset[idx], nil
}

// RebuildWeights regenerates cumulative weights from current alive proxies.
func (wr *WeightedRotator) RebuildWeights() {
	wr.mu.Lock()
	alive := getAlive(wr.proxies)
	cum := make([]int, 0, len(alive))
	subset := make([]*config.ProxyEntry, 0, len(alive))
	running := 0
	for _, p := range alive {
		w := p.Weight
		if w <= 0 {
			w = 1
		}
		running += w
		cum = append(cum, running)
		subset = append(subset, p)
	}
	wr.aliveSubset = subset
	wr.cumWeights = cum
	wr.totalWeight = running
	wr.mu.Unlock()
}

// UpdateProxies replaces proxy list and rebuilds weights.
func (wr *WeightedRotator) UpdateProxies(proxies []*config.ProxyEntry) {
	wr.mu.Lock()
	wr.proxies = proxies
	wr.mu.Unlock()
	wr.RebuildWeights()
}

// ActiveCount returns alive proxy count.
func (wr *WeightedRotator) ActiveCount() int {
	wr.mu.RLock()
	defer wr.mu.RUnlock()
	return len(getAlive(wr.proxies))
}

func (wr *WeightedRotator) IncrementConn(_ *config.ProxyEntry) {}
func (wr *WeightedRotator) DecrementConn(_ *config.ProxyEntry) {}
func (wr *WeightedRotator) Mode() string                       { return "weighted" }
