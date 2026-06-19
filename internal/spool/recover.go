package spool

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ipcap/internal/pcapio"
)

// recovered is the reconstructed durable state of a source's spool.
type recovered struct {
	sealed      map[uint64]Segment // sealed segments still relevant, by seq
	reseal      []Segment          // segments to re-append to the manifest (torn line repair)
	active      *Segment           // active segment to append to, or nil to create fresh
	head        uint64             // next gpidx to assign
	nextSeq     uint64             // seq for the next segment to be created
	oldestGpidx uint64             // StartGpidx of the oldest on-disk segment
	linkType    uint32
	snaplen     uint32
}

// recoverSpool reconstructs durable state by walking the on-disk segment files
// in sequence order and deriving each segment's gpidx range from a single
// running counter. Sealed segments take their range from the manifest; an
// unsealed file (the active segment, or a sealed one whose manifest line was
// lost to a torn write) takes its range from the running counter and is
// re-sealed. The chain is contiguous by construction, and any real
// discontinuity (a missing intermediate segment, an out-of-order range) is a
// hard error — so a crash can never silently shift or reissue a gpidx.
func recoverSpool(dir string, srcID uint16, snaplen, linkType uint32) (recovered, error) {
	r := recovered{sealed: map[uint64]Segment{}, snaplen: snaplen, linkType: linkType}

	manifest, err := loadManifest(dir)
	if err != nil {
		return r, err
	}
	sealedBySeq := make(map[uint64]Segment, len(manifest))
	var maxSealedSeq, maxSealedEnd uint64
	for _, s := range manifest {
		sealedBySeq[s.Seq] = s
		if s.Seq >= maxSealedSeq {
			maxSealedSeq = s.Seq
		}
		if s.EndGpidx > maxSealedEnd {
			maxSealedEnd = s.EndGpidx
		}
	}

	seqs, err := listSegmentFiles(dir, srcID)
	if err != nil {
		return r, err
	}

	if len(seqs) == 0 {
		// No segment files. If the manifest references segments they were
		// removed out-of-band; resume past the highest recorded gpidx so a
		// gpidx is never reissued.
		r.active = nil
		r.head = maxSealedEnd
		r.oldestGpidx = maxSealedEnd
		if len(manifest) > 0 {
			r.nextSeq = maxSealedSeq + 1
		}
		return r, nil
	}

	var running uint64
	haveRunning := false
	for i, seq := range seqs {
		isLast := i == len(seqs)-1
		if seg, ok := sealedBySeq[seq]; ok {
			if !haveRunning {
				running = seg.StartGpidx
				r.oldestGpidx = seg.StartGpidx
				haveRunning = true
			}
			if seg.StartGpidx != running {
				return r, fmt.Errorf("spool src%d: non-contiguous sealed segment seq=%d start=%d, expected %d", srcID, seq, seg.StartGpidx, running)
			}
			r.sealed[seq] = seg
			running = seg.EndGpidx
			continue
		}

		// Unsealed file: the active segment (last), or a sealed segment whose
		// manifest line was torn. Derive its range from the running counter and
		// scan it (truncating a torn tail only on the active segment).
		start := running
		if !haveRunning {
			start = 0
			running = 0
			r.oldestGpidx = 0
			haveRunning = true
		}
		validBytes, count, err := scanSegment(dir, srcID, seq, snaplen, linkType, isLast)
		if err != nil {
			return r, err
		}
		seg := Segment{
			Seq:        seq,
			File:       segmentName(srcID, seq),
			StartGpidx: start,
			EndGpidx:   start + count,
			ValidLen:   pcapio.GlobalHeaderLen + validBytes,
		}
		running = seg.EndGpidx
		if isLast {
			r.active = &seg
		} else {
			sealedSeg := seg
			sealedSeg.Sealed = true
			r.sealed[seq] = sealedSeg
			r.reseal = append(r.reseal, sealedSeg)
		}
	}

	r.head = running
	if r.active != nil {
		r.nextSeq = r.active.Seq + 1
	} else {
		r.nextSeq = seqs[len(seqs)-1] + 1
	}
	return r, nil
}

// scanSegment validates a segment's records and returns the durable byte length
// past the global header and the record count. When repair is true it opens the
// file read-write, truncates a torn tail, and resets a missing/corrupt global
// header (a crash right after create); otherwise it scans read-only and a bad
// header is a hard error.
func scanSegment(dir string, srcID uint16, seq uint64, snaplen, linkType uint32, repair bool) (validBytes int64, count uint64, err error) {
	path := filepath.Join(dir, segmentName(srcID, seq))
	flag := os.O_RDONLY
	if repair {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, 0, err
	}
	if info.Size() < pcapio.GlobalHeaderLen {
		if repair {
			return resetSegment(f, snaplen, linkType)
		}
		return 0, 0, fmt.Errorf("spool: segment %s missing global header", path)
	}
	var ghBuf [pcapio.GlobalHeaderLen]byte
	if _, err := io.ReadFull(f, ghBuf[:]); err != nil {
		return 0, 0, err
	}
	if _, err := pcapio.ParseGlobalHeader(ghBuf[:]); err != nil {
		if repair {
			return resetSegment(f, snaplen, linkType)
		}
		return 0, 0, fmt.Errorf("spool: segment %s bad global header", path)
	}

	br := bufio.NewReaderSize(f, 1<<20)
	validBytes, count, err = pcapio.ScanRecords(br, snaplen, nil)
	if err != nil {
		return 0, 0, err
	}
	want := int64(pcapio.GlobalHeaderLen) + validBytes
	if repair && info.Size() != want {
		if err := f.Truncate(want); err != nil {
			return 0, 0, fmt.Errorf("truncate torn tail: %w", err)
		}
		if err := pcapio.Fdatasync(f); err != nil {
			return 0, 0, err
		}
	}
	return validBytes, count, nil
}

// resetSegment rewrites a fresh, empty global header and truncates the file.
func resetSegment(f *os.File, snaplen, linkType uint32) (int64, uint64, error) {
	if err := f.Truncate(0); err != nil {
		return 0, 0, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	gh := pcapio.GlobalHeader{Snaplen: snaplen, LinkType: linkType}
	if _, err := f.Write(gh.AppendTo(nil)); err != nil {
		return 0, 0, err
	}
	if err := pcapio.Fdatasync(f); err != nil {
		return 0, 0, err
	}
	return 0, 0, nil
}
