package agent

import (
	"encoding/json"
	"os"
	"path/filepath"

	"ipcap/internal/pcapio"
	"ipcap/internal/proto"
)

// statsFile is where the capture process publishes its counters for the
// (separate) serve process to relay to the collector as STATS frames. Kernel
// ring drops live in the capture handle, so this is the only way the collector
// learns about pre-spool loss.
const statsFile = "stats.json"

// writeStats atomically publishes capture stats into the spool directory.
func writeStats(spoolDir string, s proto.Stats) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return pcapio.WriteFileAtomic(filepath.Join(spoolDir, statsFile), b, false)
}

// readStats reads the latest published capture stats, if any.
func readStats(spoolDir string) (proto.Stats, bool) {
	b, err := os.ReadFile(filepath.Join(spoolDir, statsFile))
	if err != nil {
		return proto.Stats{}, false
	}
	var s proto.Stats
	if err := json.Unmarshal(b, &s); err != nil {
		return proto.Stats{}, false
	}
	return s, true
}
