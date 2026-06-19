// Package metrics is a tiny, dependency-free Prometheus-text exporter. ipcap is
// deployed on RAM-constrained boxes, so rather than pull in the full client
// library we expose a handful of atomic counters/gauges in the text exposition
// format. Metrics carry a constant `src` label for per-source scraping.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

type metric struct {
	name string
	help string
	typ  string // "counter" or "gauge"
	val  atomic.Int64
}

// Counter is a monotonically increasing metric.
type Counter struct{ m *metric }

func (c *Counter) Inc()        { c.m.val.Add(1) }
func (c *Counter) Add(n int64) { c.m.val.Add(n) }

// Gauge is an arbitrary value that can go up or down.
type Gauge struct{ m *metric }

func (g *Gauge) Set(n int64) { g.m.val.Store(n) }

// Registry holds a set of metrics sharing constant labels.
type Registry struct {
	labels string
	mu     sync.Mutex
	byName map[string]*metric
}

// NewRegistry creates a registry whose metrics all carry the given constant
// labels (e.g. {"src": "1"}).
func NewRegistry(labels map[string]string) *Registry {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	enc := ""
	for i, k := range keys {
		if i > 0 {
			enc += ","
		}
		enc += k + "=" + strconv.Quote(labels[k])
	}
	if enc != "" {
		enc = "{" + enc + "}"
	}
	return &Registry{labels: enc, byName: map[string]*metric{}}
}

func (r *Registry) register(name, help, typ string) *metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.byName[name]; ok {
		return m
	}
	m := &metric{name: name, help: help, typ: typ}
	r.byName[name] = m
	return m
}

// Counter returns (registering if needed) a counter.
func (r *Registry) Counter(name, help string) *Counter {
	return &Counter{m: r.register(name, help, "counter")}
}

// Gauge returns (registering if needed) a gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	return &Gauge{m: r.register(name, help, "gauge")}
}

// Handler serves the metrics in Prometheus text exposition format.
func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		names := make([]string, 0, len(r.byName))
		for n := range r.byName {
			names = append(names, n)
		}
		sort.Strings(names)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, n := range names {
			m := r.byName[n]
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s%s %d\n",
				m.name, m.help, m.name, m.typ, m.name, r.labels, m.val.Load())
		}
		r.mu.Unlock()
	}
}

// Serve starts an HTTP metrics server on addr until it errors; intended to run
// in a goroutine.
func (r *Registry) Serve(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", r.Handler())
	return http.ListenAndServe(addr, mux)
}
