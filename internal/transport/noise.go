package transport

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

const (
	// maxNoiseMsg is the Noise transport message cap (incl. 16-byte AEAD tag).
	maxNoiseMsg = 65535
	// maxPlaintext is the largest plaintext chunk per Noise message.
	maxPlaintext = maxNoiseMsg - 16
	// HandshakeTimeout bounds the handshake so a stalled peer cannot pin a slot.
	HandshakeTimeout = 10 * time.Second
)

// ErrUnauthorized is returned when a peer's static key is not allowlisted.
var ErrUnauthorized = errors.New("transport: peer public key not authorized")

func cipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// Conn is a secure, mutually-authenticated, framed byte stream. Read and Write
// may be called concurrently (the send and receive cipher states are distinct).
type Conn interface {
	io.ReadWriteCloser
	// RemoteKey returns the authenticated static public key of the peer.
	RemoteKey() []byte
}

// Dial connects to addr and performs the IK handshake as initiator, pinning the
// responder's static key (peerPub). It authenticates the responder and proves
// our own identity to it in one round trip.
func Dial(ctx context.Context, addr string, local Keypair, peerPub []byte) (Conn, error) {
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(HandshakeTimeout))
	conn, err := clientHandshake(raw, local, peerPub)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// ServerHandshake performs the IK handshake as responder on an already-accepted
// connection, authenticating the initiator against allowed. The caller runs it
// in a per-connection goroutine (with a handshake deadline) so a stalled
// initiator cannot block the accept loop.
func ServerHandshake(raw net.Conn, local Keypair, allowed [][]byte) (Conn, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: local.Private, Public: local.Public},
	})
	if err != nil {
		return nil, err
	}
	msg1, err := readHandshakeMsg(raw)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, fmt.Errorf("transport: handshake read: %w", err)
	}
	peer := hs.PeerStatic()
	if !keyAllowed(allowed, peer) {
		return nil, ErrUnauthorized
	}
	msg2, csR2I, csI2R, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeHandshakeMsg(raw, msg2); err != nil {
		return nil, err
	}
	// Split() returns (initiator->responder, responder->initiator). As
	// responder we send with the second and receive with the first.
	return newConn(raw, csI2R, csR2I, peer), nil
}

func clientHandshake(raw net.Conn, local Keypair, peerPub []byte) (Conn, error) {
	if len(peerPub) != KeyLen {
		return nil, fmt.Errorf("transport: peer public key must be %d bytes", KeyLen)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite(),
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Private: local.Private, Public: local.Public},
		PeerStatic:    peerPub,
	})
	if err != nil {
		return nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeHandshakeMsg(raw, msg1); err != nil {
		return nil, err
	}
	msg2, err := readHandshakeMsg(raw)
	if err != nil {
		return nil, err
	}
	_, csI2R, csR2I, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("transport: handshake read: %w", err)
	}
	// As initiator we send with initiator->responder and receive with the other.
	return newConn(raw, csI2R, csR2I, peerPub), nil
}

func keyAllowed(allowed [][]byte, peer []byte) bool {
	for _, k := range allowed {
		if subtle.ConstantTimeCompare(k, peer) == 1 {
			return true
		}
	}
	return false
}

// length-prefixed framing for handshake messages (small, bounded by maxNoiseMsg).
func writeHandshakeMsg(conn net.Conn, msg []byte) error {
	if len(msg) > maxNoiseMsg {
		return errors.New("transport: handshake message too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := conn.Write(append(hdr[:], msg...)); err != nil {
		return err
	}
	return nil
}

func readHandshakeMsg(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// conn is a post-handshake secure stream over the raw TCP connection.
type conn struct {
	raw  net.Conn
	send *noise.CipherState
	recv *noise.CipherState
	peer []byte

	wmu sync.Mutex
	rmu sync.Mutex
	buf []byte // leftover decrypted plaintext
}

func newConn(raw net.Conn, send, recv *noise.CipherState, peer []byte) *conn {
	pk := make([]byte, len(peer))
	copy(pk, peer)
	return &conn{raw: raw, send: send, recv: recv, peer: pk}
}

func (c *conn) RemoteKey() []byte { return c.peer }

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlaintext {
			chunk = p[:maxPlaintext]
		}
		ct, err := c.send.Encrypt(nil, nil, chunk)
		if err != nil {
			return total, err
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
		if _, err := c.raw.Write(append(hdr[:], ct...)); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.buf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
			return 0, err
		}
		ct := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c.raw, ct); err != nil {
			return 0, err
		}
		pt, err := c.recv.Decrypt(nil, nil, ct)
		if err != nil {
			return 0, fmt.Errorf("transport: decrypt: %w", err)
		}
		c.buf = pt
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *conn) Close() error { return c.raw.Close() }
