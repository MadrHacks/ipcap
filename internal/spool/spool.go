package spool

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"ipcap/internal/pcapio"
)

// Config controls a source's spool writer.
type Config struct {
	Dir            string
	SrcID          uint16
	Snaplen        uint32
	LinkType       uint32
	RotateBytes    int64         // seal & start a new segment past this size
	RotateInterval time.Duration // ...or this much wall time
	SyncBytes      int64         // fdatasync after this many unsynced bytes
	SyncInterval   time.Duration // ...or this much time
}

func (c *Config) applyDefaults() {
	if c.RotateBytes <= 0 {
		c.RotateBytes = 64 << 20
	}
	if c.RotateInterval <= 0 {
		c.RotateInterval = 60 * time.Second
	}
	if c.SyncBytes <= 0 {
		c.SyncBytes = 64 << 10
	}
	if c.SyncInterval <= 0 {
		c.SyncInterval = 500 * time.Millisecond
	}
	if c.Snaplen == 0 {
		c.Snaplen = 65536
	}
}

// syncFile flushes a file's data to stable storage (data + size, not mtime).
func syncFile(f *os.File) error { return unix.Fdatasync(int(f.Fd())) }

// syncDir fsyncs a directory so newly created files' directory entries (names)
// are durable. fdatasync of a file flushes its contents but NOT its dirent, so
// without this a hard power cut could lose a just-created segment's name while
// keeping its bytes — regressing the durable head and reissuing gpidx.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Writer is the durable, append-only spool writer for one source. It is the
// zero-loss anchor: every packet is assigned a gpidx and appended as a whole
// libpcap record before it is eligible for delivery, and only fdatasync'd bytes
// are ever advertised to the reader.
type Writer struct {
	cfg      Config
	mu       sync.Mutex
	file     *os.File // active segment, open for append
	manifest *os.File // append-only sealed-segment log

	active  Segment
	nextSeq uint64
	sealed  map[uint64]Segment

	head        uint64 // next gpidx to assign
	oldestGpidx uint64

	fileOffset   int64  // current size of active file (may be ahead of durable)
	durableLen   int64  // fdatasync'd byte length of active file
	durableEnd   uint64 // gpidx end corresponding to durableLen
	pendingBytes int64

	segStart time.Time
	lastSync time.Time
}

// NewWriter opens (recovering as needed) the spool for a source.
func NewWriter(cfg Config) (*Writer, error) {
	cfg.applyDefaults()
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, err
	}
	rec, err := recoverSpool(cfg.Dir, cfg.SrcID, cfg.Snaplen, cfg.LinkType)
	if err != nil {
		return nil, fmt.Errorf("spool recovery: %w", err)
	}
	mf, err := os.OpenFile(filepath.Join(cfg.Dir, manifestName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	// Make the manifest's directory entry durable before it anchors any gpidx.
	if err := syncDir(cfg.Dir); err != nil {
		mf.Close()
		return nil, err
	}
	w := &Writer{
		cfg:         cfg,
		manifest:    mf,
		sealed:      rec.sealed,
		nextSeq:     rec.nextSeq,
		head:        rec.head,
		oldestGpidx: rec.oldestGpidx,
		lastSync:    time.Now(),
		segStart:    time.Now(),
	}
	// Re-seal any segment whose manifest line was lost to a torn write, so the
	// independent reader can see it again.
	for _, seg := range rec.reseal {
		if err := w.sealToManifest(seg); err != nil {
			mf.Close()
			return nil, err
		}
	}
	if rec.active != nil {
		f, err := os.OpenFile(filepath.Join(cfg.Dir, rec.active.File), os.O_RDWR, 0o644)
		if err != nil {
			mf.Close()
			return nil, err
		}
		if _, err := f.Seek(rec.active.ValidLen, io.SeekStart); err != nil {
			f.Close()
			mf.Close()
			return nil, err
		}
		w.file = f
		w.active = *rec.active
		w.fileOffset = rec.active.ValidLen
		w.durableLen = rec.active.ValidLen
		w.durableEnd = rec.active.EndGpidx
	} else {
		if err := w.openNewSegment(rec.nextSeq, rec.head); err != nil {
			mf.Close()
			return nil, err
		}
		w.nextSeq = rec.nextSeq + 1
	}
	if err := w.publishHead(); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

// openNewSegment creates a fresh segment file at the given seq starting at the
// given gpidx, writes and syncs its global header, and makes it active.
func (w *Writer) openNewSegment(seq, startGpidx uint64) error {
	name := segmentName(w.cfg.SrcID, seq)
	f, err := os.OpenFile(filepath.Join(w.cfg.Dir, name), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	gh := pcapio.GlobalHeader{Snaplen: w.cfg.Snaplen, LinkType: w.cfg.LinkType}
	if _, err := f.Write(gh.AppendTo(nil)); err != nil {
		f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		f.Close()
		return err
	}
	// Make the new segment's directory entry durable before any gpidx it covers
	// can be advertised, so a power cut cannot lose the name and regress head.
	if err := syncDir(w.cfg.Dir); err != nil {
		f.Close()
		return err
	}
	if w.file != nil {
		w.file.Close()
	}
	w.file = f
	w.active = Segment{
		Seq:        seq,
		File:       name,
		StartGpidx: startGpidx,
		EndGpidx:   startGpidx,
		ValidLen:   pcapio.GlobalHeaderLen,
	}
	w.fileOffset = pcapio.GlobalHeaderLen
	w.durableLen = pcapio.GlobalHeaderLen
	w.durableEnd = startGpidx
	w.pendingBytes = 0
	w.segStart = time.Now()
	return nil
}

// WritePacket appends one captured packet, returning the gpidx it was assigned.
// The record is written whole (a single write), then sync/rotation policy runs.
func (w *Writer) WritePacket(rec pcapio.Record) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if rec.OrigLen == 0 {
		rec.OrigLen = uint32(len(rec.Data))
	}
	buf := rec.AppendTo(nil)
	if _, err := w.file.Write(buf); err != nil {
		return 0, err
	}
	gpidx := w.head
	w.head++
	w.active.EndGpidx = w.head
	w.fileOffset += int64(len(buf))
	w.pendingBytes += int64(len(buf))

	if w.pendingBytes >= w.cfg.SyncBytes || time.Since(w.lastSync) >= w.cfg.SyncInterval {
		if err := w.sync(); err != nil {
			return gpidx, err
		}
	}
	if w.fileOffset >= w.cfg.RotateBytes || time.Since(w.segStart) >= w.cfg.RotateInterval {
		if err := w.rotate(); err != nil {
			return gpidx, err
		}
	}
	return gpidx, nil
}

// Tick performs time-based flush and rotation; the capture loop calls it
// periodically so idle periods still bound un-synced data and segment age.
func (w *Writer) Tick() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pendingBytes > 0 && time.Since(w.lastSync) >= w.cfg.SyncInterval {
		if err := w.sync(); err != nil {
			return err
		}
	}
	if w.fileOffset > pcapio.GlobalHeaderLen && time.Since(w.segStart) >= w.cfg.RotateInterval {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	return nil
}

// sync fdatasyncs the active segment and advertises the new durable head.
func (w *Writer) sync() error {
	if err := syncFile(w.file); err != nil {
		return err
	}
	w.durableLen = w.fileOffset
	w.durableEnd = w.head
	w.pendingBytes = 0
	w.lastSync = time.Now()
	return w.publishHead()
}

// publishHead atomically advertises the active segment's durable extent.
func (w *Writer) publishHead() error {
	return writeHead(w.cfg.Dir, Segment{
		Seq:        w.active.Seq,
		File:       w.active.File,
		StartGpidx: w.active.StartGpidx,
		EndGpidx:   w.durableEnd,
		ValidLen:   w.durableLen,
		Sealed:     false,
	})
}

// rotate makes the current segment durable, seals it into the manifest, and
// opens the next one. Ordering guarantees a crash leaves a consistent spool.
func (w *Writer) rotate() error {
	if err := w.sync(); err != nil {
		return err
	}
	sealed := Segment{
		Seq:        w.active.Seq,
		File:       w.active.File,
		StartGpidx: w.active.StartGpidx,
		EndGpidx:   w.durableEnd,
		ValidLen:   w.durableLen,
		Sealed:     true,
	}
	if err := w.sealToManifest(sealed); err != nil {
		return err
	}
	seq := w.nextSeq
	w.nextSeq++
	if err := w.openNewSegment(seq, w.head); err != nil {
		return err
	}
	return w.publishHead()
}

// sealToManifest appends a sealed segment record to the manifest and fdatasyncs
// it, then records it in the in-memory sealed set.
func (w *Writer) sealToManifest(seg Segment) error {
	seg.Sealed = true
	line, err := json.Marshal(seg)
	if err != nil {
		return err
	}
	if _, err := w.manifest.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := syncFile(w.manifest); err != nil {
		return err
	}
	w.sealed[seg.Seq] = seg
	return nil
}

// Head returns the next gpidx that will be assigned (the in-memory head).
func (w *Writer) Head() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head
}

// OldestGpidx returns the StartGpidx of the oldest retained segment.
func (w *Writer) OldestGpidx() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.oldestGpidx
}

// Close flushes and closes the spool.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	if w.file != nil {
		if w.pendingBytes > 0 {
			if serr := w.sync(); serr != nil {
				err = serr
			}
		}
		if cerr := w.file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if w.manifest != nil {
		if cerr := w.manifest.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}
