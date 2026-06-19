package collector

import (
	"ipcap/internal/metrics"
	"ipcap/internal/proto"
)

// Metrics is the collector's observable state. Agent-side values arrive as
// cumulative snapshots in STATS frames, so they are exposed as gauges set to the
// latest total.
type Metrics struct {
	committed   *metrics.Gauge
	lag         *metrics.Gauge
	bytes       *metrics.Counter
	gaps        *metrics.Counter
	reconnects  *metrics.Counter
	corrupt     *metrics.Counter
	captured    *metrics.Gauge
	kernelDrops *metrics.Gauge
	ifdrops     *metrics.Gauge
	spoolBytes  *metrics.Gauge
}

// NewMetrics registers the collector's metrics on reg.
func NewMetrics(reg *metrics.Registry) *Metrics {
	return &Metrics{
		committed:   reg.Gauge("ipcap_collector_committed_gpidx", "Highest committed packet index (exclusive)"),
		lag:         reg.Gauge("ipcap_collector_lag_gpidx", "Packets the collector trails the agent head by"),
		bytes:       reg.Counter("ipcap_collector_committed_bytes_total", "Bytes durably committed to the mirror"),
		gaps:        reg.Counter("ipcap_collector_gaps_total", "Bounded retention-wrap losses observed"),
		reconnects:  reg.Counter("ipcap_collector_reconnects_total", "Drain reconnects"),
		corrupt:     reg.Counter("ipcap_collector_corrupt_frames_total", "Frames rejected for CRC/format errors"),
		captured:    reg.Gauge("ipcap_agent_captured_total", "Packets captured by the agent"),
		kernelDrops: reg.Gauge("ipcap_agent_kernel_drops_total", "Packets dropped by the kernel ring (pre-spool)"),
		ifdrops:     reg.Gauge("ipcap_agent_ifdrops_total", "Packets dropped by the interface"),
		spoolBytes:  reg.Gauge("ipcap_agent_spool_bytes", "Agent spool size in bytes"),
	}
}

// The update methods are nil-safe so a metrics-less collector (and tests) can
// pass a nil *Metrics.

func (m *Metrics) onCommit(committed uint64, bytes int) {
	if m == nil {
		return
	}
	m.committed.Set(int64(committed))
	m.bytes.Add(int64(bytes))
}

func (m *Metrics) onGap() {
	if m != nil {
		m.gaps.Inc()
	}
}

func (m *Metrics) onReconnect() {
	if m != nil {
		m.reconnects.Inc()
	}
}

func (m *Metrics) onCorrupt() {
	if m != nil {
		m.corrupt.Inc()
	}
}

func (m *Metrics) onLag(head, committed uint64) {
	if m == nil {
		return
	}
	if head > committed {
		m.lag.Set(int64(head - committed))
	} else {
		m.lag.Set(0)
	}
}

func (m *Metrics) onStats(s proto.Stats) {
	if m == nil {
		return
	}
	m.captured.Set(int64(s.Captured))
	m.kernelDrops.Set(int64(s.DroppedKern))
	m.ifdrops.Set(int64(s.IfDrop))
	m.spoolBytes.Set(int64(s.SpoolBytes))
}
