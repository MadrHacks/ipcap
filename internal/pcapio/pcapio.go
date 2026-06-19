// Package pcapio is the single source of truth for the classic libpcap byte
// format: the 24-byte global header and 16-byte-prefixed records, plus a
// forward record scanner used for crash recovery. Output is byte-identical to
// what pcap.OpenOfflineFile (the tulip assembler), suricata -r, and tshark
// expect, so spool files, the collector mirror, and the re-served PCAP-over-IP
// stream all share this encoder.
package pcapio

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// MagicMicros selects microsecond timestamp resolution (classic libpcap),
	// matching tulip's own pcapgo dumps for maximum downstream compatibility.
	MagicMicros uint32 = 0xa1b2c3d4

	GlobalHeaderLen = 24
	RecordHeaderLen = 16

	versionMajor = 2
	versionMinor = 4
)

// GlobalHeader is the libpcap file header.
type GlobalHeader struct {
	Snaplen  uint32
	LinkType uint32
}

// AppendTo serialises the 24-byte global header (little-endian) onto dst.
func (g GlobalHeader) AppendTo(dst []byte) []byte {
	var h [GlobalHeaderLen]byte
	binary.LittleEndian.PutUint32(h[0:], MagicMicros)
	binary.LittleEndian.PutUint16(h[4:], versionMajor)
	binary.LittleEndian.PutUint16(h[6:], versionMinor)
	binary.LittleEndian.PutUint32(h[8:], 0)  // thiszone
	binary.LittleEndian.PutUint32(h[12:], 0) // sigfigs
	binary.LittleEndian.PutUint32(h[16:], g.Snaplen)
	binary.LittleEndian.PutUint32(h[20:], g.LinkType)
	return append(dst, h[:]...)
}

// WriteGlobalHeader writes the global header to w.
func (g GlobalHeader) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(g.AppendTo(nil))
	return int64(n), err
}

var ErrBadGlobalHeader = errors.New("pcapio: bad global header")

// ParseGlobalHeader reads a 24-byte global header from b. Only the classic
// microsecond magic is accepted (the only format this package writes).
func ParseGlobalHeader(b []byte) (GlobalHeader, error) {
	if len(b) < GlobalHeaderLen {
		return GlobalHeader{}, ErrBadGlobalHeader
	}
	if binary.LittleEndian.Uint32(b[0:]) != MagicMicros {
		return GlobalHeader{}, ErrBadGlobalHeader
	}
	return GlobalHeader{
		Snaplen:  binary.LittleEndian.Uint32(b[16:]),
		LinkType: binary.LittleEndian.Uint32(b[20:]),
	}, nil
}

// Record is one packet in libpcap on-disk form. Data length is CapLen.
type Record struct {
	TsSec   uint32
	TsUsec  uint32
	OrigLen uint32
	Data    []byte
}

// Size is the on-disk byte size of the record (header + body).
func (r Record) Size() int { return RecordHeaderLen + len(r.Data) }

// AppendTo serialises the record (16-byte header + body) onto dst as one
// contiguous slice, so the caller can write it with a single whole-record Write.
func (r Record) AppendTo(dst []byte) []byte {
	var h [RecordHeaderLen]byte
	binary.LittleEndian.PutUint32(h[0:], r.TsSec)
	binary.LittleEndian.PutUint32(h[4:], r.TsUsec)
	binary.LittleEndian.PutUint32(h[8:], uint32(len(r.Data)))
	binary.LittleEndian.PutUint32(h[12:], r.OrigLen)
	dst = append(dst, h[:]...)
	return append(dst, r.Data...)
}

// ScanRecords reads records sequentially from r (positioned just after the
// global header), validating each against snaplen, invoking onRecord for every
// fully-valid record. It stops at a clean EOF or at the first torn/implausible
// record (a partially-written tail after a hard crash), returning the number of
// valid bytes consumed past the global header and the count of valid records.
//
// A torn tail is not an error: the caller truncates the file to
// GlobalHeaderLen+validBytes to restore it to the last whole record.
func ScanRecords(r io.Reader, snaplen uint32, onRecord func(Record) error) (validBytes int64, count uint64, err error) {
	var hdr [RecordHeaderLen]byte
	for {
		n, rerr := io.ReadFull(r, hdr[:])
		if rerr == io.EOF && n == 0 {
			return validBytes, count, nil // clean boundary
		}
		if rerr == io.ErrUnexpectedEOF || (rerr == io.EOF && n != 0) {
			return validBytes, count, nil // torn header
		}
		if rerr != nil {
			return validBytes, count, rerr
		}
		capLen := binary.LittleEndian.Uint32(hdr[8:])
		if capLen > snaplen {
			return validBytes, count, nil // implausible length: torn/corrupt tail
		}
		data := make([]byte, capLen)
		if _, rerr := io.ReadFull(r, data); rerr != nil {
			return validBytes, count, nil // torn body
		}
		rec := Record{
			TsSec:   binary.LittleEndian.Uint32(hdr[0:]),
			TsUsec:  binary.LittleEndian.Uint32(hdr[4:]),
			OrigLen: binary.LittleEndian.Uint32(hdr[12:]),
			Data:    data,
		}
		if onRecord != nil {
			if cerr := onRecord(rec); cerr != nil {
				return validBytes, count, cerr
			}
		}
		validBytes += int64(RecordHeaderLen) + int64(capLen)
		count++
	}
}

// ReadRecord reads exactly one record from r, validating it against snaplen.
// It returns io.EOF at a clean record boundary and io.ErrUnexpectedEOF on a
// torn record (used by the tailing reader, which only reads up to a durable,
// whole-record offset and so never legitimately sees a torn record).
func ReadRecord(r io.Reader, snaplen uint32) (Record, error) {
	var hdr [RecordHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Record{}, err
	}
	capLen := binary.LittleEndian.Uint32(hdr[8:])
	if capLen > snaplen {
		return Record{}, ErrBadGlobalHeader
	}
	data := make([]byte, capLen)
	if _, err := io.ReadFull(r, data); err != nil {
		if err == io.EOF {
			return Record{}, io.ErrUnexpectedEOF
		}
		return Record{}, err
	}
	return Record{
		TsSec:   binary.LittleEndian.Uint32(hdr[0:]),
		TsUsec:  binary.LittleEndian.Uint32(hdr[4:]),
		OrigLen: binary.LittleEndian.Uint32(hdr[12:]),
		Data:    data,
	}, nil
}
