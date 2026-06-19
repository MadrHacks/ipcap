package capture

import (
	"os"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
)

// FileSource replays a libpcap file as a packet source. It is the path tests
// exercise end-to-end, and also serves offline reprocessing.
type FileSource struct {
	f        *os.File
	r        *pcapgo.Reader
	linkType uint32
	count    uint64
}

// OpenFile opens a libpcap file (microsecond or nanosecond) as a Source.
func OpenFile(path string) (*FileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &FileSource{f: f, r: r, linkType: uint32(r.LinkType())}, nil
}

func (s *FileSource) ReadPacket() (time.Time, []byte, int, error) {
	data, ci, err := s.r.ReadPacketData()
	if err != nil {
		return time.Time{}, nil, 0, err
	}
	s.count++
	ts := ci.Timestamp
	if ts.IsZero() {
		ts = time.Unix(0, 0)
	}
	return ts, data, ci.Length, nil
}

func (s *FileSource) LinkType() uint32 { return s.linkType }

func (s *FileSource) Stats() (Stats, error) { return Stats{Received: s.count}, nil }

func (s *FileSource) Close() error { return s.f.Close() }
