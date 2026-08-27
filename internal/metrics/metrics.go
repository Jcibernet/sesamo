// Package metrics provides a dependency-free Prometheus exposition. We
// only need a handful of counters and a latency histogram for the
// introspect hot path, so a tiny stdlib implementation beats pulling in
// the official client library (and its transitive deps).
package metrics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
)

// Registry holds all metrics. Safe for concurrent use.
type Registry struct {
	mu         sync.RWMutex
	counters   map[string]*atomic.Int64
	gauges     map[string]*atomic.Uint64 // float64 bits
	histograms map[string]*histogram
}

// New constructs a Registry.
func New() *Registry {
	return &Registry{
		counters:   make(map[string]*atomic.Int64),
		gauges:     make(map[string]*atomic.Uint64),
		histograms: make(map[string]*histogram),
	}
}

// IncCounter increments a named counter (optionally with a label set
// encoded into the name by the caller, e.g. "http_requests_total").
func (r *Registry) IncCounter(name string) {
	r.mu.RLock()
	c, ok := r.counters[name]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		if c, ok = r.counters[name]; !ok {
			c = new(atomic.Int64)
			r.counters[name] = c
		}
		r.mu.Unlock()
	}
	c.Add(1)
}

// Observe records a value (seconds) into a named histogram.
func (r *Registry) Observe(name string, v float64) {
	r.mu.RLock()
	h, ok := r.histograms[name]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		if h, ok = r.histograms[name]; !ok {
			h = newHistogram()
			r.histograms[name] = h
		}
		r.mu.Unlock()
	}
	h.observe(v)
}

// SetGauge publishes the current value of a named gauge. Unlike a
// counter, a gauge answers "how bad is it right now" — queue depth and
// the age of the oldest pending job are only meaningful as levels.
func (r *Registry) SetGauge(name string, v float64) {
	r.mu.RLock()
	g, ok := r.gauges[name]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		if g, ok = r.gauges[name]; !ok {
			g = new(atomic.Uint64)
			r.gauges[name] = g
		}
		r.mu.Unlock()
	}
	g.Store(math.Float64bits(v))
}

// histogram with fixed buckets tuned for sub-second auth latencies.
type histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
	total   uint64
}

func newHistogram() *histogram {
	return &histogram{
		buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		counts:  make([]uint64, 11), // len(buckets)+1 for +Inf
	}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.buckets)]++ // +Inf bucket
}

// WritePrometheus renders all metrics in the Prometheus text format.
func (r *Registry) WritePrometheus() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var b []byte
	names := make([]string, 0, len(r.counters))
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b = append(b, fmt.Sprintf("# TYPE %s counter\n%s %d\n",
			n, n, r.counters[n].Load())...)
	}

	gnames := make([]string, 0, len(r.gauges))
	for n := range r.gauges {
		gnames = append(gnames, n)
	}
	sort.Strings(gnames)
	for _, n := range gnames {
		b = append(b, fmt.Sprintf("# TYPE %s gauge\n%s %g\n",
			n, n, math.Float64frombits(r.gauges[n].Load()))...)
	}

	hnames := make([]string, 0, len(r.histograms))
	for n := range r.histograms {
		hnames = append(hnames, n)
	}
	sort.Strings(hnames)
	for _, n := range hnames {
		h := r.histograms[n]
		h.mu.Lock()
		b = append(b, fmt.Sprintf("# TYPE %s histogram\n", n)...)
		var cumulative uint64
		for i, bound := range h.buckets {
			cumulative += h.counts[i]
			b = append(b, fmt.Sprintf("%s_bucket{le=\"%g\"} %d\n", n, bound, cumulative)...)
		}
		cumulative += h.counts[len(h.buckets)]
		b = append(b, fmt.Sprintf("%s_bucket{le=\"+Inf\"} %d\n", n, cumulative)...)
		b = append(b, fmt.Sprintf("%s_sum %g\n%s_count %d\n", n, h.sum, n, h.total)...)
		h.mu.Unlock()
	}
	return string(b)
}
