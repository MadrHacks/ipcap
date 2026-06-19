// Package transport is ipcap's sole link transport: a mutually-authenticated,
// encrypted, framed byte stream over TCP using the Noise Protocol (IK pattern,
// Curve25519 + ChaCha20-Poly1305 + SHA-256). The static-IP vulnbox agent
// listens; the dynamic-IP collector dials. Each side has one static keypair;
// the agent allowlists collector public keys and the collector pins the agent's
// public key. No PKI, no certificates, no SSH.
package transport

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// KeyLen is the length of a Curve25519 key in bytes.
const KeyLen = 32

// Keypair is a node's static Curve25519 identity.
type Keypair struct {
	Private []byte
	Public  []byte
}

// Generate creates a new random static keypair.
func Generate() (Keypair, error) {
	k, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: k.Private, Public: k.Public}, nil
}

// PublicB64 / PrivateB64 render the keys as standard base64.
func (k Keypair) PublicB64() string  { return base64.StdEncoding.EncodeToString(k.Public) }
func (k Keypair) PrivateB64() string { return base64.StdEncoding.EncodeToString(k.Private) }

// keypairFromPrivate derives the public key from a 32-byte private key.
func keypairFromPrivate(priv []byte) (Keypair, error) {
	if len(priv) != KeyLen {
		return Keypair{}, fmt.Errorf("transport: private key must be %d bytes, got %d", KeyLen, len(priv))
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: priv, Public: pub}, nil
}

// ParsePrivateKey loads a keypair from a base64 private key.
func ParsePrivateKey(b64 string) (Keypair, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return Keypair{}, fmt.Errorf("transport: decode private key: %w", err)
	}
	return keypairFromPrivate(priv)
}

// ParsePublicKey decodes a base64 public key, validating its length.
func ParsePublicKey(b64 string) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("transport: decode public key: %w", err)
	}
	if len(pub) != KeyLen {
		return nil, fmt.Errorf("transport: public key must be %d bytes, got %d", KeyLen, len(pub))
	}
	return pub, nil
}

// ParsePublicKeys decodes a list of base64 public keys.
func ParsePublicKeys(b64s []string) ([][]byte, error) {
	out := make([][]byte, 0, len(b64s))
	for _, s := range b64s {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		pub, err := ParsePublicKey(s)
		if err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, nil
}

// LoadPrivateKeyFile reads a base64 private key from a file (first non-empty,
// non-comment line), so the secret lives only on disk on each node.
func LoadPrivateKeyFile(path string) (Keypair, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Keypair{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return ParsePrivateKey(line)
	}
	return Keypair{}, errors.New("transport: no private key found in file")
}
