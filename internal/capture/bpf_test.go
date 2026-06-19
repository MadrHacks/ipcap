package capture

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func ethIPv4TCP(srcPort, dstPort uint16, src, dst [4]byte) []byte {
	b := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(b[12:], etherTypeIPv4)
	b[14] = 0x45 // IPv4, IHL 5
	b[14+9] = ipProtoTCP
	copy(b[14+12:], src[:])
	copy(b[14+16:], dst[:])
	binary.BigEndian.PutUint16(b[34:], srcPort)
	binary.BigEndian.PutUint16(b[36:], dstPort)
	return b
}

func vlanEthIPv4TCP(dstPort uint16) []byte {
	b := make([]byte, 14+4+20+20)
	binary.BigEndian.PutUint16(b[12:], etherTypeVLAN)
	binary.BigEndian.PutUint16(b[16:], etherTypeIPv4) // inner ether type
	b[18] = 0x45
	b[18+9] = ipProtoTCP
	binary.BigEndian.PutUint16(b[18+20+2:], dstPort)
	return b
}

func TestExcluderSSHPort(t *testing.T) {
	e := NewExcluder(uint32(layers.LinkTypeEthernet), 22, nil)
	host := [4]byte{10, 0, 0, 5}
	peer := [4]byte{10, 0, 0, 9}

	if !e.Exclude(ethIPv4TCP(54321, 22, peer, host)) {
		t.Error("inbound SSH (dst 22) should be excluded")
	}
	if !e.Exclude(ethIPv4TCP(22, 54321, host, peer)) {
		t.Error("outbound SSH (src 22) should be excluded")
	}
	if e.Exclude(ethIPv4TCP(1234, 5678, peer, host)) {
		t.Error("non-SSH game traffic should be kept")
	}
	if !e.Exclude(vlanEthIPv4TCP(22)) {
		t.Error("VLAN-tagged SSH should be excluded")
	}
}

func TestExcluderCustomPortAndHost(t *testing.T) {
	e := NewExcluder(uint32(layers.LinkTypeEthernet), 2222, []string{"10.0.0.1", "192.168.9.0/24"})
	host := [4]byte{10, 0, 0, 5}
	peer := [4]byte{10, 0, 0, 9}

	if !e.Exclude(ethIPv4TCP(40000, 2222, peer, host)) {
		t.Error("SSH on custom port 2222 should be excluded")
	}
	if e.Exclude(ethIPv4TCP(40000, 22, peer, host)) {
		t.Error("port 22 should NOT be excluded when ssh-port is 2222")
	}
	if !e.Exclude(ethIPv4TCP(1234, 5678, [4]byte{10, 0, 0, 1}, peer)) {
		t.Error("traffic from mgmt host 10.0.0.1 should be excluded")
	}
	if !e.Exclude(ethIPv4TCP(1234, 5678, peer, [4]byte{192, 168, 9, 50})) {
		t.Error("traffic to mgmt CIDR 192.168.9.0/24 should be excluded")
	}
}

// TestExcluderNeverPanics feeds truncated and garbage inputs; a single panic in
// the capture hot path would let an attacker crash-loop the agent.
func TestExcluderNeverPanics(t *testing.T) {
	e := NewExcluder(uint32(layers.LinkTypeEthernet), 22, []string{"10.0.0.1"})
	full := ethIPv4TCP(54321, 22, [4]byte{10, 0, 0, 9}, [4]byte{10, 0, 0, 5})

	// Every truncation length.
	for n := 0; n <= len(full); n++ {
		e.Exclude(full[:n])
	}
	// Pathological inputs: empty, all-VLAN, deep nesting, bogus link types.
	cases := [][]byte{
		{},
		{0x81, 0x00},
		make([]byte, 4),
	}
	deepVLAN := make([]byte, 14)
	binary.BigEndian.PutUint16(deepVLAN[12:], etherTypeVLAN)
	for i := 0; i < 64; i++ {
		chunk := []byte{0x81, 0x00, 0x00, 0x00}
		deepVLAN = append(deepVLAN, chunk...)
	}
	cases = append(cases, deepVLAN)
	for _, c := range cases {
		e.Exclude(c) // must not panic
	}

	raw := NewExcluder(uint32(layers.LinkTypeRaw), 22, nil)
	for n := 0; n <= 44; n++ {
		raw.Exclude(full[14 : 14+min(n, len(full)-14)])
	}
}
