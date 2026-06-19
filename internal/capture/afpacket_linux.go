//go:build linux

package capture

import (
	"errors"
	"os"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

// AFPacketSource captures from a live interface via AF_PACKET TPACKETv3 with a
// large mmap ring, so brief consumer or restart stalls do not drop packets in
// the kernel.
type AFPacketSource struct {
	tp       *afpacket.TPacket
	linkType uint32
}

// OpenAFPacket binds a TPACKETv3 ring (~ringMiB MiB) to iface.
func OpenAFPacket(iface string, ringMiB, snaplen int) (*AFPacketSource, error) {
	if ringMiB <= 0 {
		ringMiB = 256
	}
	if snaplen <= 0 {
		snaplen = 65536
	}
	frameSize, blockSize, numBlocks, err := computeRing(ringMiB, snaplen, os.Getpagesize())
	if err != nil {
		return nil, err
	}
	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptPollTimeout(100*time.Millisecond),
		afpacket.OptBlockTimeout(10*time.Millisecond),
	)
	if err != nil {
		return nil, err
	}
	return &AFPacketSource{tp: tp, linkType: uint32(layers.LinkTypeEthernet)}, nil
}

func (s *AFPacketSource) ReadPacket() (time.Time, []byte, int, error) {
	data, ci, err := s.tp.ZeroCopyReadPacketData()
	if err != nil {
		if err == afpacket.ErrTimeout {
			return time.Time{}, nil, 0, ErrTimeout
		}
		return time.Time{}, nil, 0, err
	}
	return ci.Timestamp, data, ci.Length, nil
}

func (s *AFPacketSource) LinkType() uint32 { return s.linkType }

func (s *AFPacketSource) Stats() (Stats, error) {
	_, v3, err := s.tp.SocketStats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{
		Received:      uint64(v3.Packets()),
		DroppedKernel: uint64(v3.Drops()),
	}, nil
}

func (s *AFPacketSource) Close() error {
	s.tp.Close()
	return nil
}

// computeRing derives TPACKETv3 ring geometry sized to roughly targetMiB,
// following gopacket's afpacket sizing recipe.
func computeRing(targetMiB, snaplen, pageSize int) (frameSize, blockSize, numBlocks int, err error) {
	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}
	blockSize = frameSize * 128
	numBlocks = (targetMiB * 1024 * 1024) / blockSize
	if numBlocks == 0 {
		return 0, 0, 0, errors.New("afpacket: ring target too small")
	}
	return frameSize, blockSize, numBlocks, nil
}
