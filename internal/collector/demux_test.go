package collector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"ipcap/internal/pcapio"
	"ipcap/internal/proto"
)

func dpayload(i int) []byte { return []byte(fmt.Sprintf("demux-pkt-%08d", i)) }

func protoRec(i int) proto.PktRecord {
	d := dpayload(i)
	return proto.PktRecord{TsSec: uint64(i), CapLen: uint32(len(d)), OrigLen: uint32(len(d)), Data: d}
}

// TestDemuxDedupMidBatch feeds a batch that straddles the commit point: the
// prefix is already committed (must be dropped) and only the suffix is written,
// with no duplication or loss.
func TestDemuxDedupMidBatch(t *testing.T) {
	dir := t.TempDir()
	gh := pcapio.GlobalHeader{Snaplen: 65536, LinkType: 1}
	mirror, err := OpenMirror(dir, 1, gh)
	if err != nil {
		t.Fatal(err)
	}
	defer mirror.Close()

	// Pre-commit packets 0..49.
	pre := make([]pcapio.Record, 50)
	for i := range pre {
		pre[i] = protoToPcap(protoRec(i))
	}
	if err := mirror.Append(pre, 0); err != nil {
		t.Fatal(err)
	}
	if mirror.Committed() != 50 {
		t.Fatalf("pre-commit = %d, want 50", mirror.Committed())
	}

	// Batch base=30 covering gpidx 30..69: 30..49 are duplicates, 50..69 new.
	d := NewDemux(1, "t", mirror, io.Discard, nil, nil)
	batch := make([]proto.PktRecord, 40)
	for i := range batch {
		batch[i] = protoRec(30 + i)
	}
	if err := d.commit(30, batch, 1); err != nil {
		t.Fatal(err)
	}
	if mirror.Committed() != 70 {
		t.Fatalf("post-commit = %d, want 70 (dropped 20 dups, kept 20)", mirror.Committed())
	}
	mirror.Close()

	// Mirror must hold exactly 70 contiguous records, gpidx-correct.
	f, _ := os.Open(filepath.Join(dir, mirrorName(1, 0)))
	defer f.Close()
	var ghb [pcapio.GlobalHeaderLen]byte
	io.ReadFull(f, ghb[:])
	idx := 0
	_, count, err := pcapio.ScanRecords(f, 65536, func(rec pcapio.Record) error {
		if string(rec.Data) != string(dpayload(idx)) {
			return fmt.Errorf("record %d mismatch: %q", idx, rec.Data)
		}
		idx++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 70 {
		t.Fatalf("mirror has %d records, want 70", count)
	}
}

// TestDoubleCollectorFlock asserts a second collector cannot lock the same
// mirror directory while the first holds it.
func TestDoubleCollectorFlock(t *testing.T) {
	dir := t.TempDir()
	unlock, err := flockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flockDir(dir); err == nil {
		t.Fatal("second collector should not acquire the mirror lock")
	}
	unlock()
	unlock2, err := flockDir(dir)
	if err != nil {
		t.Fatalf("lock should be re-acquirable after release: %v", err)
	}
	unlock2()
}

// TestDemuxEpochResetRealignsCommit verifies the spool-wipe self-heal: when the
// agent advertises a new spool epoch, the mirror realigns its commit point to
// the fresh stream's base instead of stalling forever on a stale gpidx the new
// spool will never reach (which is what happens if dedup keeps dropping the
// fresh low-gpidx packets as "already committed").
func TestDemuxEpochResetRealignsCommit(t *testing.T) {
	dir := t.TempDir()
	gh := pcapio.GlobalHeader{Snaplen: 65536, LinkType: 1}
	mirror, err := OpenMirror(dir, 1, gh)
	if err != nil {
		t.Fatal(err)
	}
	defer mirror.Close()

	// Old epoch "A": commit 100 packets.
	recs := make([]pcapio.Record, 100)
	for i := range recs {
		recs[i] = protoToPcap(protoRec(i))
	}
	if err := mirror.Append(recs, 1); err != nil {
		t.Fatal(err)
	}

	d := NewDemux(1, "t", mirror, io.Discard, nil, nil)

	// First contact records the epoch without moving the commit point.
	if err := d.reconcileEpoch("A", 100); err != nil {
		t.Fatal(err)
	}
	if mirror.Committed() != 100 || mirror.Epoch() != "A" {
		t.Fatalf("adopt: commit=%d epoch=%q, want 100/A", mirror.Committed(), mirror.Epoch())
	}

	// Same epoch on reconnect: no change.
	if err := d.reconcileEpoch("A", 100); err != nil {
		t.Fatal(err)
	}
	if mirror.Committed() != 100 {
		t.Fatalf("same-epoch moved commit to %d", mirror.Committed())
	}

	// New epoch "B" (spool wiped): the fresh spool serves from gpidx 0, so the
	// mirror must realign there and rotate to a new session.
	sessBefore := mirror.state.SessionSeq
	if err := d.reconcileEpoch("B", 0); err != nil {
		t.Fatal(err)
	}
	if mirror.Committed() != 0 || mirror.Epoch() != "B" {
		t.Fatalf("reset: commit=%d epoch=%q, want 0/B", mirror.Committed(), mirror.Epoch())
	}
	if mirror.state.SessionSeq <= sessBefore {
		t.Fatalf("epoch reset did not rotate session (%d <= %d)", mirror.state.SessionSeq, sessBefore)
	}

	// The realigned stream now accepts the fresh spool's gpidx 0.. — which under
	// the stale commit point would have been dropped as duplicates indefinitely.
	fresh := make([]proto.PktRecord, 10)
	for i := range fresh {
		fresh[i] = protoRec(i)
	}
	if err := d.commit(0, fresh, 2); err != nil {
		t.Fatal(err)
	}
	if mirror.Committed() != 10 {
		t.Fatalf("post-reset commit=%d, want 10", mirror.Committed())
	}

	// The realignment must survive a collector restart (durably persisted).
	mirror.Close()
	re, err := OpenMirror(dir, 1, gh)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if re.Epoch() != "B" || re.Committed() != 10 {
		t.Fatalf("reopened: epoch=%q commit=%d, want B/10", re.Epoch(), re.Committed())
	}
}
