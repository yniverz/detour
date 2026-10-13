// Package metrics provides a few counters in Prometheus text exposition format
// without external dependencies.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// Metrics holds detour's counters.
type Metrics struct {
	Requests       counterVec // by status class: 2xx, 3xx, 4xx, 5xx
	Rejected       counterVec // by reason
	UpstreamErrors atomic.Int64
	Retries        atomic.Int64
	MarkedDown     atomic.Int64
	InFlight       atomic.Int64
}

type counterVec struct {
	mu sync.Mutex
	m  map[string]int64
}

// Inc increments the counter for label.
func (c *counterVec) Inc(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int64{}
	}
	c.m[label]++
}

func (c *counterVec) snapshot() ([]string, map[string]int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.m))
	cp := make(map[string]int64, len(c.m))
	for k, v := range c.m {
		keys = append(keys, k)
		cp[k] = v
	}
	sort.Strings(keys)
	return keys, cp
}

// StatusClass maps a status code to "2xx" etc.
func StatusClass(code int) string {
	if code < 100 || code > 599 {
		return "other"
	}
	return fmt.Sprintf("%dxx", code/100)
}

// WriteTo writes all metrics; downOrigins is the current number of upstreams marked down.
func (m *Metrics) WriteTo(w io.Writer, downOrigins int) {
	writeVec(w, "detour_requests_total", "Requests handled, by response status class.", "class", &m.Requests)
	writeVec(w, "detour_rejected_total", "Requests rejected before proxying, by reason.", "reason", &m.Rejected)
	writeCounter(w, "detour_upstream_errors_total", "Failed upstream attempts (transport errors and configured fail statuses).", m.UpstreamErrors.Load())
	writeCounter(w, "detour_retries_total", "Requests retried on another upstream.", m.Retries.Load())
	writeCounter(w, "detour_upstreams_marked_down_total", "Times an upstream was marked down by passive health checks.", m.MarkedDown.Load())
	fmt.Fprintf(w, "# HELP detour_inflight_requests Requests currently being proxied.\n# TYPE detour_inflight_requests gauge\ndetour_inflight_requests %d\n", m.InFlight.Load())
	fmt.Fprintf(w, "# HELP detour_upstreams_down Upstreams currently marked down.\n# TYPE detour_upstreams_down gauge\ndetour_upstreams_down %d\n", downOrigins)
}

func writeCounter(w io.Writer, name, help string, v int64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
}

func writeVec(w io.Writer, name, help, label string, c *counterVec) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys, vals := c.snapshot()
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, vals[k])
	}
}
