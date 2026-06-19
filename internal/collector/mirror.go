// Package collector implements the tulip-host side: the Noise supervisor that
// drains a vulnbox agent, the frame demux with gpidx dedupe and strict-order
// durable commit, and the per-source mirror feeding the PCAP-over-IP re-serve.
package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"

	"ipcap/internal/pcapio"
)

// ResumeState is the collector's durable, per-source commit point. CommittedGpidx
// is half-open: every packet with gpidx < CommittedGpidx is durably in the
// mirror. A session is one gap-free run of gpidx written to one mirror file.
type ResumeState struct {
	CommittedGpidx    uint64 `json:"committed"`
	SessionSeq        uint64 `json:"session"`
	SessionStartGpidx uint64 `json:"session_start"`
	LastSeq           uint64 `json:"last_seq"`
}

// Mirror is the durable, Wireshark-openable copy of a source's committed
// packets on the tulip host, plus the authoritative resume point.
type Mirror struct {
	dir     string
	srcID   uint16
	gh      pcapio.GlobalHeader
	file    *os.File
	fileLen int64       // durable byte length of the active session file
	state   ResumeState // owned by the single demux goroutine

	// Atomics for safe concurrent reads (supervisor resume, lag, and the
	// PCAP-over-IP fan-out tailing the mirror) without touching writer state.
	committed    atomic.Uint64
	sessionStart atomic.Uint64
	sessionSeq   atomic.Uint64
	committedLen atomic.Int64
}

// publish copies the writer-owned commit point into the atomically-readable
// fields after any durable state change.
func (m *Mirror) publish() {
	m.committed.Store(m.state.CommittedGpidx)
	m.sessionStart.Store(m.state.SessionStartGpidx)
	m.sessionSeq.Store(m.state.SessionSeq)
	m.committedLen.Store(m.fileLen)
}

// Snapshot returns the current fan-out view: the active session, its on-disk
// file, the durable byte length the fan-out may read up to, and the libpcap
// header. Safe to call concurrently with the writer.
func (m *Mirror) Snapshot() (sessionSeq uint64, file string, committedLen int64, gh pcapio.GlobalHeader) {
	return m.sessionSeq.Load(),
		filepath.Join(m.dir, mirrorName(m.srcID, m.sessionSeq.Load())),
		m.committedLen.Load(),
		m.gh
}

func mirrorName(srcID uint16, sessionSeq uint64) string {
	return fmt.Sprintf("mirror-src%d-%020d.pcap", srcID, sessionSeq)
}

func resumePath(dir string, srcID uint16) string {
	return filepath.Join(dir, fmt.Sprintf("resume-src%d.json", srcID))
}

// OpenMirror loads the resume state and reopens (recovering by truncate-to-
// committed) the active session mirror file.
func OpenMirror(dir string, srcID uint16, gh pcapio.GlobalHeader) (*Mirror, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	m := &Mirror{dir: dir, srcID: srcID, gh: gh}
	if err := m.loadState(); err != nil {
		return nil, err
	}
	if err := m.openSession(); err != nil {
		return nil, err
	}
	m.publish()
	return m, nil
}

func (m *Mirror) loadState() error {
	b, err := os.ReadFile(resumePath(m.dir, m.srcID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh: zero state
		}
		return err
	}
	return json.Unmarshal(b, &m.state)
}

// openSession opens the current session file and truncates it to exactly the
// committed record count, discarding any un-acked tail written before a crash.
func (m *Mirror) openSession() error {
	path := filepath.Join(m.dir, mirrorName(m.srcID, m.state.SessionSeq))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if info.Size() < pcapio.GlobalHeaderLen {
		// Fresh or torn header: rewrite a clean global header.
		if err := f.Truncate(0); err != nil {
			f.Close()
			return err
		}
		if _, err := f.Write(m.gh.AppendTo(nil)); err != nil {
			f.Close()
			return err
		}
	} else {
		// Recover: keep exactly the committed records, drop any un-acked tail.
		want := m.state.CommittedGpidx - m.state.SessionStartGpidx
		offset, have, err := recordOffsetForCount(f, m.gh.Snaplen, want)
		if err != nil {
			f.Close()
			return err
		}
		if have < want {
			// Mirror is shorter than the recorded commit point (should not
			// happen): trust the file and lower the commit point.
			log.Printf("collector: mirror src%d shorter than committed (%d<%d); lowering", m.srcID, have, want)
			m.state.CommittedGpidx = m.state.SessionStartGpidx + have
		}
		if err := f.Truncate(offset); err != nil {
			f.Close()
			return err
		}
	}
	if err := pcapio.Fdatasync(f); err != nil {
		f.Close()
		return err
	}
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return err
	}
	m.file = f
	m.fileLen = off
	return nil
}

// recordOffsetForCount returns the byte offset just past the want-th record and
// the number of records actually present (<= want), without modifying the file.
func recordOffsetForCount(f *os.File, snaplen uint32, want uint64) (offset int64, have uint64, err error) {
	offset = pcapio.GlobalHeaderLen
	var hdr [pcapio.RecordHeaderLen]byte
	for have < want {
		if _, err := f.ReadAt(hdr[:], offset); err != nil {
			return offset, have, nil // EOF/short: fewer records than want
		}
		capLen, _ := pcapio.ParseRecordHeader(hdr[:])
		if capLen > snaplen {
			return offset, have, nil
		}
		offset += int64(pcapio.RecordHeaderLen) + int64(capLen)
		have++
	}
	return offset, have, nil
}

// Committed returns the half-open commit point (next gpidx needed). Safe to
// call concurrently with the writer.
func (m *Mirror) Committed() uint64 { return m.committed.Load() }

// SetHeader adopts the link type learned from the agent preamble so the durable
// mirror, the spool, and the re-served stream all declare one consistent link
// type (the hardcoded Ethernet default is only correct for AF_PACKET). It
// rewrites the on-disk global header only while the current session is still
// empty; a later session (after a GAP) picks it up via NewSession.
func (m *Mirror) SetHeader(h pcapio.GlobalHeader) error {
	if m.gh == h {
		return nil
	}
	m.gh = h
	if m.state.CommittedGpidx != m.state.SessionStartGpidx {
		return nil // session already has records; header is fixed for this file
	}
	if err := m.file.Truncate(0); err != nil {
		return err
	}
	if _, err := m.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := m.file.Write(m.gh.AppendTo(nil)); err != nil {
		return err
	}
	if err := pcapio.Fdatasync(m.file); err != nil {
		return err
	}
	_, err := m.file.Seek(0, io.SeekEnd)
	return err
}

// Append durably commits a contiguous run of records beginning at the current
// commit point, in strict order: append bytes, fdatasync the mirror, then
// fsync the advanced resume state. Only after this returns may the records be
// handed to fan-out. lastSeq is the wire Seq of the frame that carried them.
func (m *Mirror) Append(recs []pcapio.Record, lastSeq uint64) error {
	if len(recs) == 0 {
		return nil
	}
	var buf []byte
	for _, r := range recs {
		buf = r.AppendTo(buf)
	}
	if _, err := m.file.Write(buf); err != nil {
		return err
	}
	if err := pcapio.Fdatasync(m.file); err != nil {
		return err
	}
	m.fileLen += int64(len(buf))
	m.state.CommittedGpidx += uint64(len(recs))
	m.state.LastSeq = lastSeq
	if err := m.persistState(); err != nil {
		return err
	}
	m.publish()
	return nil
}

// NewSession rotates to a fresh mirror file starting at startGpidx, used after a
// GAP so each mirror file is gap-free and the assembler restarts cleanly.
func (m *Mirror) NewSession(startGpidx uint64) error {
	if m.file != nil {
		m.file.Close()
	}
	m.state.SessionSeq++
	m.state.SessionStartGpidx = startGpidx
	m.state.CommittedGpidx = startGpidx
	if err := m.openSession(); err != nil {
		return err
	}
	if err := m.persistState(); err != nil {
		return err
	}
	m.publish()
	return nil
}

// persistState atomically writes resume.json and fsyncs it (and its directory).
func (m *Mirror) persistState() error {
	b, err := json.Marshal(m.state)
	if err != nil {
		return err
	}
	return pcapio.WriteFileAtomic(resumePath(m.dir, m.srcID), b, true)
}

// Close flushes and closes the mirror file.
func (m *Mirror) Close() error {
	if m.file != nil {
		err := m.file.Close()
		m.file = nil
		return err
	}
	return nil
}
