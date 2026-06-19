package capture

import (
	"encoding/binary"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// Excluder drops the SSH drain and management traffic so the agent never
// captures, spools, or re-serves its own control path (which would otherwise
// amplify without bound). In milestone 1 this is enforced in userspace, before
// any packet is spooled.
//
// The match runs on every captured packet — adversary-controlled bytes on a
// CTF game network — so it is a strictly bounded, allocation-free, panic-proof
// manual header parse (fixed offsets, no unbounded loops, every access length-
// checked). It deliberately does NOT use a general packet decoder, which an
// attacker could feed pathological input to stall or crash the capture hot path.
type Excluder struct {
	linkType uint32
	sshPort  uint16
	hosts    []net.IP
	nets     []*net.IPNet
}

// NewExcluder builds an excluder for a link type and SSH port. mgmt entries may
// be bare IPs or CIDRs; traffic to or from any of them is excluded, as is any
// TCP segment on the SSH port (sshPort <= 0 disables the port rule).
func NewExcluder(linkType uint32, sshPort int, mgmt []string) *Excluder {
	e := &Excluder{linkType: linkType}
	if sshPort > 0 && sshPort <= 0xFFFF {
		e.sshPort = uint16(sshPort)
	}
	for _, m := range mgmt {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if strings.Contains(m, "/") {
			if _, n, err := net.ParseCIDR(m); err == nil {
				e.nets = append(e.nets, n)
			}
			continue
		}
		if ip := net.ParseIP(m); ip != nil {
			e.hosts = append(e.hosts, ip)
		}
	}
	return e
}

// Active reports whether the excluder has any rule, so callers can skip the
// per-packet parse entirely when nothing is excluded.
func (e *Excluder) Active() bool {
	return e.sshPort != 0 || len(e.hosts) > 0 || len(e.nets) > 0
}

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86DD
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88A8
	ipProtoTCP    = 6
)

// Exclude reports whether the packet is SSH/management traffic to be dropped.
// It returns false (keep) for anything it cannot fully parse, so it can never
// be made to do unbounded work and never wrongly excludes game traffic.
func (e *Excluder) Exclude(data []byte) bool {
	if !e.Active() {
		return false
	}
	l3, ethType, ok := e.l3Offset(data)
	if !ok {
		return false
	}
	switch ethType {
	case etherTypeIPv4:
		return e.checkIPv4(data, l3)
	case etherTypeIPv6:
		return e.checkIPv6(data, l3)
	default:
		return false
	}
}

// l3Offset returns the byte offset and ether type of the L3 header for the
// configured link type. It tolerates up to a couple of stacked VLAN tags.
func (e *Excluder) l3Offset(data []byte) (int, uint16, bool) {
	switch e.linkType {
	case uint32(layers.LinkTypeEthernet):
		off := 14
		if len(data) < off {
			return 0, 0, false
		}
		ethType := binary.BigEndian.Uint16(data[12:14])
		for tags := 0; (ethType == etherTypeVLAN || ethType == etherTypeQinQ) && tags < 3; tags++ {
			if len(data) < off+4 {
				return 0, 0, false
			}
			ethType = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
		return off, ethType, true
	case uint32(layers.LinkTypeRaw), uint32(layers.LinkTypeIPv4), uint32(layers.LinkTypeIPv6):
		if len(data) < 1 {
			return 0, 0, false
		}
		switch data[0] >> 4 {
		case 4:
			return 0, etherTypeIPv4, true
		case 6:
			return 0, etherTypeIPv6, true
		default:
			return 0, 0, false
		}
	default:
		return 0, 0, false
	}
}

func (e *Excluder) checkIPv4(data []byte, l3 int) bool {
	if len(data) < l3+20 {
		return false
	}
	if len(e.hosts) > 0 || len(e.nets) > 0 {
		if e.matchHost(data[l3+12:l3+16]) || e.matchHost(data[l3+16:l3+20]) {
			return true
		}
	}
	if e.sshPort == 0 || data[l3+9] != ipProtoTCP {
		return false
	}
	ihl := int(data[l3]&0x0f) * 4
	if ihl < 20 {
		return false
	}
	return e.matchTCPPort(data, l3+ihl)
}

func (e *Excluder) checkIPv6(data []byte, l3 int) bool {
	if len(data) < l3+40 {
		return false
	}
	if len(e.hosts) > 0 || len(e.nets) > 0 {
		if e.matchHost(data[l3+8:l3+24]) || e.matchHost(data[l3+24:l3+40]) {
			return true
		}
	}
	// Only the common case (TCP directly after the fixed header) is matched;
	// SSH never rides IPv6 extension-header chains in practice, and not matching
	// only means we keep a packet, never that we wrongly drop game traffic.
	if e.sshPort == 0 || data[l3+6] != ipProtoTCP {
		return false
	}
	return e.matchTCPPort(data, l3+40)
}

func (e *Excluder) matchTCPPort(data []byte, tcpOff int) bool {
	if len(data) < tcpOff+4 {
		return false
	}
	src := binary.BigEndian.Uint16(data[tcpOff : tcpOff+2])
	dst := binary.BigEndian.Uint16(data[tcpOff+2 : tcpOff+4])
	return src == e.sshPort || dst == e.sshPort
}

func (e *Excluder) matchHost(raw []byte) bool {
	ip := net.IP(raw)
	for _, h := range e.hosts {
		if h.Equal(ip) {
			return true
		}
	}
	for _, n := range e.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
