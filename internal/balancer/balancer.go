// Package balancer orders upstream targets for a request according to a
// balancing policy and passive health state.
package balancer

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yniverz/detour/internal/target"
)

// Policy selects how the first upstream is chosen.
type Policy string

const (
	RoundRobin Policy = "roundrobin"
	Random     Policy = "random"
	Failover   Policy = "failover"
	IPHash     Policy = "iphash"
	LeastConn  Policy = "leastconn"
)

// ParsePolicy validates a policy name (case-insensitive, a few aliases).
func ParsePolicy(s string) (Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "roundrobin", "round-robin", "rr":
		return RoundRobin, nil
	case "random":
		return Random, nil
	case "failover", "first", "priority":
		return Failover, nil
	case "iphash", "ip-hash", "sticky":
		return IPHash, nil
	case "leastconn", "least-conn", "leastconnections":
		return LeastConn, nil
	}
	return "", fmt.Errorf("unknown policy %q (roundrobin, random, failover, iphash, leastconn)", s)
}

// Health tracks passive health per upstream origin.
type Health struct {
	MaxFails    int
	FailTimeout time.Duration

	mu sync.Mutex
	m  map[string]*originState
}

type originState struct {
	fails     int
	downUntil time.Time
	inflight  atomic.Int64
}

// NewHealth creates a health tracker. maxFails <= 0 disables marking upstreams down.
func NewHealth(maxFails int, failTimeout time.Duration) *Health {
	return &Health{MaxFails: maxFails, FailTimeout: failTimeout, m: map[string]*originState{}}
}

func (h *Health) state(origin string) *originState {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.m[origin]
	if !ok {
		s = &originState{}
		h.m[origin] = s
	}
	return s
}

// Available reports whether origin is not currently marked down.
func (h *Health) Available(origin string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.m[origin]
	return !ok || !now.Before(s.downUntil)
}

// Failure records a failed attempt; returns true if the origin is now marked down.
func (h *Health) Failure(origin string, now time.Time) bool {
	if h.MaxFails <= 0 {
		return false
	}
	s := h.state(origin)
	h.mu.Lock()
	defer h.mu.Unlock()
	s.fails++
	if s.fails >= h.MaxFails {
		s.fails = 0
		s.downUntil = now.Add(h.FailTimeout)
		return true
	}
	return false
}

// Success clears the failure counter of origin.
func (h *Health) Success(origin string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.m[origin]; ok {
		s.fails = 0
		s.downUntil = time.Time{}
	}
}

// Acquire increments the in-flight counter; call the returned func when done.
func (h *Health) Acquire(origin string) func() {
	s := h.state(origin)
	s.inflight.Add(1)
	var once sync.Once
	return func() { once.Do(func() { s.inflight.Add(-1) }) }
}

func (h *Health) inflight(origin string) int64 {
	h.mu.Lock()
	s, ok := h.m[origin]
	h.mu.Unlock()
	if !ok {
		return 0
	}
	return s.inflight.Load()
}

// Down returns the origins currently marked down (for metrics/debugging).
func (h *Health) Down(now time.Time) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for o, s := range h.m {
		if now.Before(s.downUntil) {
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return out
}

// Balancer keeps per-pool round-robin state. A pool is identified by its
// canonical target list, so identical headers share state.
type Balancer struct {
	Health   *Health
	MaxPools int

	mu    sync.Mutex
	pools map[string]*poolState
	now   func() time.Time
}

type poolState struct {
	current  map[string]int // smooth weighted round-robin state per origin
	lastUsed time.Time
}

// New creates a balancer.
func New(h *Health, maxPools int) *Balancer {
	if maxPools <= 0 {
		maxPools = 1024
	}
	return &Balancer{Health: h, MaxPools: maxPools, pools: map[string]*poolState{}, now: time.Now}
}

// PoolKey returns the canonical identity of a target list.
func PoolKey(ts []target.Target) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = t.String()
	}
	return strings.Join(parts, ",")
}

// Order returns all targets ordered by preference: available primaries (policy
// order), available backups, then unavailable primaries and backups as a last
// resort. clientKey is used by the iphash policy.
func (b *Balancer) Order(ts []target.Target, policy Policy, clientKey string) []target.Target {
	now := b.now()
	var upP, upB, downP, downB []target.Target
	for _, t := range ts {
		up := b.Health.Available(t.Origin(), now)
		switch {
		case up && !t.Backup:
			upP = append(upP, t)
		case up:
			upB = append(upB, t)
		case !t.Backup:
			downP = append(downP, t)
		default:
			downB = append(downB, t)
		}
	}
	key := PoolKey(ts)
	out := make([]target.Target, 0, len(ts))
	out = append(out, b.orderGroup(key+"|p", upP, policy, clientKey)...)
	out = append(out, b.orderGroup(key+"|b", upB, policy, clientKey)...)
	out = append(out, downP...)
	out = append(out, downB...)
	return out
}

func (b *Balancer) orderGroup(key string, ts []target.Target, policy Policy, clientKey string) []target.Target {
	if len(ts) <= 1 {
		return ts
	}
	switch policy {
	case Failover:
		return ts
	case Random:
		return rotateTo(ts, weightedRandom(ts))
	case IPHash:
		return rendezvous(ts, clientKey)
	case LeastConn:
		return b.leastConn(ts)
	default:
		return rotateTo(ts, b.smoothWRR(key, ts))
	}
}

// smoothWRR implements nginx-style smooth weighted round-robin over ts.
func (b *Balancer) smoothWRR(key string, ts []target.Target) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	ps, ok := b.pools[key]
	if !ok {
		b.evictLocked()
		ps = &poolState{current: map[string]int{}}
		b.pools[key] = ps
	}
	ps.lastUsed = b.now()
	total, best, bestW := 0, -1, math.MinInt
	for i, t := range ts {
		id := t.String()
		ps.current[id] += t.Weight
		total += t.Weight
		if ps.current[id] > bestW {
			best, bestW = i, ps.current[id]
		}
	}
	ps.current[ts[best].String()] -= total
	return best
}

func (b *Balancer) evictLocked() {
	if len(b.pools) < b.MaxPools {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, p := range b.pools {
		if oldestKey == "" || p.lastUsed.Before(oldest) {
			oldestKey, oldest = k, p.lastUsed
		}
	}
	delete(b.pools, oldestKey)
}

func (b *Balancer) leastConn(ts []target.Target) []target.Target {
	type scored struct {
		t     target.Target
		score float64
		idx   int
	}
	s := make([]scored, len(ts))
	for i, t := range ts {
		s[i] = scored{t, float64(b.Health.inflight(t.Origin())) / float64(t.Weight), i}
	}
	sort.SliceStable(s, func(i, j int) bool { return s[i].score < s[j].score })
	out := make([]target.Target, len(ts))
	for i := range s {
		out[i] = s[i].t
	}
	return out
}

func weightedRandom(ts []target.Target) int {
	total := 0
	for _, t := range ts {
		total += t.Weight
	}
	n := rand.IntN(total)
	for i, t := range ts {
		if n < t.Weight {
			return i
		}
		n -= t.Weight
	}
	return 0
}

// rendezvous orders targets by weighted highest-random-weight hashing of
// clientKey, so a client keeps its upstream while it stays available.
func rendezvous(ts []target.Target, clientKey string) []target.Target {
	type scored struct {
		t     target.Target
		score float64
	}
	s := make([]scored, len(ts))
	for i, t := range ts {
		h := fnv.New64a()
		h.Write([]byte(clientKey))
		h.Write([]byte{0})
		h.Write([]byte(t.String()))
		// Map the hash to (0,1) and apply the weighted HRW formula.
		u := (float64(mix64(h.Sum64())>>11) + 0.5) / float64(1<<53)
		s[i] = scored{t, -float64(t.Weight) / math.Log(u)}
	}
	sort.SliceStable(s, func(i, j int) bool { return s[i].score > s[j].score })
	out := make([]target.Target, len(ts))
	for i := range s {
		out[i] = s[i].t
	}
	return out
}

// mix64 is the splitmix64 finalizer. FNV-1a alone mixes the high bits poorly
// for short keys that differ only in their last bytes.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func rotateTo(ts []target.Target, first int) []target.Target {
	out := make([]target.Target, 0, len(ts))
	out = append(out, ts[first:]...)
	return append(out, ts[:first]...)
}
