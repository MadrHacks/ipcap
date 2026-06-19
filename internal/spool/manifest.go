// Package spool implements the agent's durable, Wireshark-openable on-disk
// capture spool: rotating libpcap segments, an fsynced gpidx anchor manifest,
// crash recovery by forward record scan, and a read-only tailing reader used by
// the serve process. gpidx (per-source monotonic packet index) is the single
// resume coordinate; every durable artifact records the gpidx range it covers.
package spool

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ipcap/internal/pcapio"
)

// Segment describes one spool file's gpidx coverage. EndGpidx is exclusive:
// the segment holds packets with gpidx in [StartGpidx, EndGpidx). ValidLen is
// the durable byte length (including the 24-byte global header) that has been
// fdatasync'd; readers must never read past it.
type Segment struct {
	Seq        uint64 `json:"seq"`
	File       string `json:"file"`
	StartGpidx uint64 `json:"start"`
	EndGpidx   uint64 `json:"end"`
	ValidLen   int64  `json:"vlen"`
	Sealed     bool   `json:"sealed"`
}

const (
	manifestName = "manifest.ndjson"
	headName     = "head.json"
)

// segmentName builds the on-disk name for a source's segment. The sequence is
// zero-padded so lexical and numeric order agree, and is monotonic (never
// wall-clock) so rotation order is stable across clock steps.
func segmentName(srcID uint16, seq uint64) string {
	return fmt.Sprintf("src%d-%020d.pcap", srcID, seq)
}

// parseSegmentSeq extracts the sequence from a segment filename, or false.
func parseSegmentSeq(name string) (uint64, bool) {
	if !strings.HasSuffix(name, ".pcap") {
		return 0, false
	}
	i := strings.LastIndex(name, "-")
	if i < 0 {
		return 0, false
	}
	seq, err := strconv.ParseUint(strings.TrimSuffix(name[i+1:], ".pcap"), 10, 64)
	if err != nil {
		return 0, false
	}
	return seq, true
}

// loadManifest reads the append-only sealed-segment manifest, keeping the last
// record per sequence and silently ignoring a torn final line (a crash during
// append). Entries are returned ordered by sequence.
func loadManifest(dir string) ([]Segment, error) {
	f, err := os.Open(filepath.Join(dir, manifestName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	bySeq := map[uint64]Segment{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var seg Segment
		if err := json.Unmarshal(line, &seg); err != nil {
			// Torn/partial trailing line after a crash: stop, keep prior lines.
			break
		}
		bySeq[seg.Seq] = seg
	}
	segs := make([]Segment, 0, len(bySeq))
	for _, s := range bySeq {
		segs = append(segs, s)
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].Seq < segs[j].Seq })
	return segs, nil
}

// readHead reads the live active-segment pointer, if present. It is a hint for
// the tailing reader (the durable head it may read up to); recovery never
// trusts it and rebuilds it by scanning, so it is written atomically but is not
// required to be crash-durable.
func readHead(dir string) (Segment, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, headName))
	if err != nil {
		if os.IsNotExist(err) {
			return Segment{}, false, nil
		}
		return Segment{}, false, err
	}
	var seg Segment
	if err := json.Unmarshal(b, &seg); err != nil {
		return Segment{}, false, nil // torn write; treat as absent
	}
	return seg, true, nil
}

// writeHead atomically publishes the active-segment pointer via temp+rename.
func writeHead(dir string, seg Segment) error {
	b, err := json.Marshal(seg)
	if err != nil {
		return err
	}
	return pcapio.WriteFileAtomic(filepath.Join(dir, headName), b, false)
}

// listSegmentFiles returns the sequences of all segment files for srcID on disk,
// sorted ascending.
func listSegmentFiles(dir string, srcID uint16) ([]uint64, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("src%d-", srcID)
	var seqs []uint64
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if seq, ok := parseSegmentSeq(e.Name()); ok {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}
