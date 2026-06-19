package spool

import (
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// SpoolBytes returns the total on-disk size of this source's segments.
func (w *Writer) SpoolBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.spoolBytesLocked()
}

func (w *Writer) spoolBytesLocked() int64 {
	seqs, err := listSegmentFiles(w.cfg.Dir, w.cfg.SrcID)
	if err != nil {
		return 0
	}
	var total int64
	for _, seq := range seqs {
		if info, err := os.Stat(filepath.Join(w.cfg.Dir, segmentName(w.cfg.SrcID, seq))); err == nil {
			total += info.Size()
		}
	}
	return total
}

// Reap enforces the byte cap by deleting whole sealed segments oldest-first. It
// never deletes the active segment, and never a segment a reader holds a shared
// lock on (so bytes are never yanked from under an in-flight serve). It returns
// the number of segments removed. Forced drops advance oldestGpidx, which a
// later serve resume turns into an explicit GAP — the only, bounded, loss mode.
func (w *Writer) Reap(maxBytes int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if maxBytes <= 0 {
		return 0, nil
	}

	total := w.spoolBytesLocked()
	if total <= maxBytes {
		return 0, nil
	}

	// Candidates: sealed segments whose files still exist, oldest first.
	sealedSeqs := make([]uint64, 0, len(w.sealed))
	for seq := range w.sealed {
		if seq == w.active.Seq {
			continue
		}
		if _, err := os.Stat(filepath.Join(w.cfg.Dir, segmentName(w.cfg.SrcID, seq))); err == nil {
			sealedSeqs = append(sealedSeqs, seq)
		}
	}
	sort.Slice(sealedSeqs, func(i, j int) bool {
		return w.sealed[sealedSeqs[i]].StartGpidx < w.sealed[sealedSeqs[j]].StartGpidx
	})

	deleted := 0
	for _, seq := range sealedSeqs {
		if total <= maxBytes {
			break
		}
		seg := w.sealed[seq]
		path := filepath.Join(w.cfg.Dir, seg.File)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !tryReap(path) {
			break // oldest is locked by a reader; stop (don't skip ahead and reorder)
		}
		total -= info.Size()
		if seg.EndGpidx > w.oldestGpidx {
			w.oldestGpidx = seg.EndGpidx
		}
		delete(w.sealed, seq)
		deleted++
	}
	return deleted, nil
}

// tryReap deletes path iff no reader holds a shared lock on it (exclusive,
// non-blocking lock acquisition succeeds).
func tryReap(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false
	}
	if err := os.Remove(path); err != nil {
		return false
	}
	return true
}
