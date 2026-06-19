package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestNoiseRoundTrip(t *testing.T) {
	agent, _ := Generate()
	collector, _ := Generate()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		sc, err := ServerHandshake(raw, agent, [][]byte{collector.Public})
		if err != nil {
			srvErr <- err
			return
		}
		defer sc.Close()
		if !bytes.Equal(sc.RemoteKey(), collector.Public) {
			srvErr <- io.ErrUnexpectedEOF
			return
		}
		// Echo a large payload to exercise multi-message chunking.
		buf := make([]byte, 200000)
		if _, err := io.ReadFull(sc, buf); err != nil {
			srvErr <- err
			return
		}
		if _, err := sc.Write(buf); err != nil {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := Dial(ctx, ln.Addr().String(), collector, agent.Public)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	if !bytes.Equal(cc.RemoteKey(), agent.Public) {
		t.Fatal("client did not authenticate agent key")
	}

	payload := bytes.Repeat([]byte("ipcap-noise-"), 200000/12+1)[:200000]
	if _, err := cc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 200000)
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip payload mismatch")
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestNoiseRejectsUnknownPeer(t *testing.T) {
	agent, _ := Generate()
	collector, _ := Generate()
	stranger, _ := Generate()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		// Allowlist contains only the collector; the stranger must be rejected.
		_, err = ServerHandshake(raw, agent, [][]byte{collector.Public})
		raw.Close() // the accept loop closes the raw conn on handshake failure
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Stranger knows the agent's public key but is not allowlisted.
	cc, err := Dial(ctx, ln.Addr().String(), stranger, agent.Public)
	if cc != nil {
		cc.Close()
	}
	serr := <-done
	if serr != ErrUnauthorized {
		t.Fatalf("server should reject unknown peer, got %v", serr)
	}
	_ = err
}

func TestKeyEncoding(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePrivateKey(k.PrivateB64())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Public, k2.Public) {
		t.Fatal("derived public key mismatch after private round-trip")
	}
	pub, err := ParsePublicKey(k.PublicB64())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, k.Public) {
		t.Fatal("public key round-trip mismatch")
	}
}
