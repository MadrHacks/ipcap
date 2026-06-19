package spool

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"

	"ipcap/internal/pcapio"
)

var (
	// ErrNoData means the reader has caught up to the durable head; the caller
	// should idle (heartbeat) and retry — more packets may arrive.
	ErrNoData = errors.New("spool: caught up to durable head")
	// ErrReaped means the requested gpidx is older than retention; the caller
	// must emit a GAP and resume from Oldest().
	ErrReaped = errors.New("spool: requested gpidx older than retention")
)

// Reader is a read-only, tailing view of a source's spool, used by the serve
// process. It never reads past the durably fdatasync'd head advertised by the
// writer, so the collector can never commit a gpidx the agent might reissue.
type Reader struct {
	dir     string
	srcID   uint16
	snaplen uint32

	view   []Segment // durable segments, sorted by StartGpidx
	oldest uint64    // StartGpidx of oldest retained segment
	head   uint64    // exclusive durable head gpidx

	gpidx   uint64   // next gpidx to read
	file    *os.File // currently open segment
	fileSeq uint64
	offset  int64 // next byte offset in file
}

// OpenReader opens a tailing reader positioned at fromGpidx. If fromGpidx is
// older than retention it is clamped to Oldest() and (clamped, true) is
// returned so the caller can emit a GAP for the lost range.
func OpenReader(dir string, srcID uint16, snaplen uint32, fromGpidx uint64) (*Reader, uint64, bool, error) {
	r := &Reader{dir: dir, srcID: srcID, snaplen: snaplen, fileSeq: ^uint64(0)}
	if err := r.refresh(); err != nil {
		return nil, 0, false, err
	}
	reaped := false
	if fromGpidx < r.oldest {
		fromGpidx = r.oldest
		reaped = true
	}
	if fromGpidx > r.head {
		fromGpidx = r.head // newer than head (shouldn't happen): clamp, serve from head
	}
	r.gpidx = fromGpidx
	return r, fromGpidx, reaped, nil
}

// Head returns the exclusive durable head gpidx as of the last refresh.
func (r *Reader) Head() uint64 { return r.head }

// Oldest returns the oldest retained gpidx as of the last refresh.
func (r *Reader) Oldest() uint64 { return r.oldest }

// Pos returns the next gpidx the reader will return.
func (r *Reader) Pos() uint64 { return r.gpidx }

// refresh rebuilds the durable segment view from the manifest plus the active
// head pointer, intersected with the segment files actually present on disk.
func (r *Reader) refresh() error {
	seqs, err := listSegmentFiles(r.dir, r.srcID)
	if err != nil {
		return err
	}
	exists := make(map[uint64]bool, len(seqs))
	for _, s := range seqs {
		exists[s] = true
	}
	sealed, err := loadManifest(r.dir)
	if err != nil {
		return err
	}
	bySeq := make(map[uint64]Segment, len(sealed))
	for _, s := range sealed {
		if exists[s.Seq] {
			bySeq[s.Seq] = s
		}
	}
	if active, ok, err := readHead(r.dir); err != nil {
		return err
	} else if ok && exists[active.Seq] {
		bySeq[active.Seq] = active // durable End/ValidLen for the active segment
	}

	view := make([]Segment, 0, len(bySeq))
	for _, s := range bySeq {
		view = append(view, s)
	}
	sort.Slice(view, func(i, j int) bool { return view[i].StartGpidx < view[j].StartGpidx })

	r.view = view
	if len(view) == 0 {
		r.oldest, r.head = 0, 0
		return nil
	}
	r.oldest = view[0].StartGpidx
	r.head = view[len(view)-1].EndGpidx
	return nil
}

// owning returns the durable segment containing gpidx, or false.
func (r *Reader) owning(gpidx uint64) (Segment, bool) {
	for _, s := range r.view {
		if gpidx >= s.StartGpidx && gpidx < s.EndGpidx {
			return s, true
		}
	}
	return Segment{}, false
}

// Next returns the next record (with its gpidx). It returns ErrNoData when
// caught up to the durable head and ErrReaped when the position fell behind
// retention.
func (r *Reader) Next() (pcapio.Record, uint64, error) {
	for {
		if r.gpidx < r.oldest {
			return pcapio.Record{}, 0, ErrReaped
		}
		if r.gpidx >= r.head {
			if err := r.refresh(); err != nil {
				return pcapio.Record{}, 0, err
			}
			if r.gpidx < r.oldest {
				return pcapio.Record{}, 0, ErrReaped
			}
			if r.gpidx >= r.head {
				return pcapio.Record{}, 0, ErrNoData
			}
		}
		seg, ok := r.owning(r.gpidx)
		if !ok {
			// Hole between durable segments (e.g. mid-rotation view): retry.
			if err := r.refresh(); err != nil {
				return pcapio.Record{}, 0, err
			}
			if _, ok := r.owning(r.gpidx); !ok {
				return pcapio.Record{}, 0, ErrNoData
			}
			continue
		}
		if r.file == nil || r.fileSeq != seg.Seq {
			if err := r.position(seg, r.gpidx); err != nil {
				return pcapio.Record{}, 0, err
			}
		}
		rec, ok, err := r.readAt(seg)
		if err != nil {
			return pcapio.Record{}, 0, err
		}
		if !ok {
			// Not enough durable bytes yet in this segment: refresh and retry.
			if err := r.refresh(); err != nil {
				return pcapio.Record{}, 0, err
			}
			if r.gpidx >= r.head {
				return pcapio.Record{}, 0, ErrNoData
			}
			continue
		}
		gp := r.gpidx
		r.gpidx++
		return rec, gp, nil
	}
}

// position opens seg and advances to the byte offset of targetGpidx by skipping
// whole records from the segment start.
func (r *Reader) position(seg Segment, targetGpidx uint64) error {
	f, err := os.Open(filepath.Join(r.dir, seg.File))
	if err != nil {
		return err
	}
	// Hold a shared lock so the janitor's exclusive, non-blocking reap skips
	// the segment we are actively replaying.
	_ = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	if r.file != nil {
		r.file.Close()
	}
	r.file = f
	r.fileSeq = seg.Seq
	r.offset = pcapio.GlobalHeaderLen
	gp := seg.StartGpidx
	var hdr [pcapio.RecordHeaderLen]byte
	for gp < targetGpidx {
		if _, err := f.ReadAt(hdr[:], r.offset); err != nil {
			return err
		}
		capLen := binary.LittleEndian.Uint32(hdr[8:])
		r.offset += int64(pcapio.RecordHeaderLen) + int64(capLen)
		gp++
	}
	return nil
}

// readAt reads the record at the current offset if fully within seg's durable
// extent. ok is false when not enough durable bytes are present yet.
func (r *Reader) readAt(seg Segment) (pcapio.Record, bool, error) {
	if r.offset+pcapio.RecordHeaderLen > seg.ValidLen {
		return pcapio.Record{}, false, nil
	}
	var hdr [pcapio.RecordHeaderLen]byte
	if _, err := r.file.ReadAt(hdr[:], r.offset); err != nil {
		return pcapio.Record{}, false, err
	}
	capLen := binary.LittleEndian.Uint32(hdr[8:])
	if capLen > r.snaplen {
		return pcapio.Record{}, false, errors.New("spool: corrupt record in durable region")
	}
	end := r.offset + int64(pcapio.RecordHeaderLen) + int64(capLen)
	if end > seg.ValidLen {
		return pcapio.Record{}, false, nil
	}
	data := make([]byte, capLen)
	if _, err := r.file.ReadAt(data, r.offset+pcapio.RecordHeaderLen); err != nil {
		return pcapio.Record{}, false, err
	}
	r.offset = end
	return pcapio.Record{
		TsSec:   binary.LittleEndian.Uint32(hdr[0:]),
		TsUsec:  binary.LittleEndian.Uint32(hdr[4:]),
		OrigLen: binary.LittleEndian.Uint32(hdr[12:]),
		Data:    data,
	}, true, nil
}

// Close releases the open segment file.
func (r *Reader) Close() error {
	if r.file != nil {
		err := r.file.Close()
		r.file = nil
		return err
	}
	return nil
}

// SourceHeader reads a source's link type and snaplen from its newest segment's
// global header. It errors if the source has no segments yet.
func SourceHeader(dir string, srcID uint16) (pcapio.GlobalHeader, error) {
	seqs, err := listSegmentFiles(dir, srcID)
	if err != nil {
		return pcapio.GlobalHeader{}, err
	}
	if len(seqs) == 0 {
		return pcapio.GlobalHeader{}, os.ErrNotExist
	}
	f, err := os.Open(filepath.Join(dir, segmentName(srcID, seqs[len(seqs)-1])))
	if err != nil {
		return pcapio.GlobalHeader{}, err
	}
	defer f.Close()
	var gh [pcapio.GlobalHeaderLen]byte
	if _, err := f.ReadAt(gh[:], 0); err != nil {
		return pcapio.GlobalHeader{}, err
	}
	return pcapio.ParseGlobalHeader(gh[:])
}
