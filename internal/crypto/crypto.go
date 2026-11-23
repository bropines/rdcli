// Package crypto implements the RustDesk session cryptography: verifying the
// signed identities hbbs and the peer present, the key exchange, the
// secretbox stream cipher (key exchange versions 0 and 1) and the password
// challenge.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"google.golang.org/protobuf/proto"

	"github.com/bropines/rdcli/internal/pb"
)

// KxVersionLatest is the newest key exchange version rdcli speaks. Version 0
// is the original scheme (one key for both directions); version 1 derives one
// key per direction bound to the handshake transcript.
const KxVersionLatest uint32 = 1

// KxParamsDomain prefixes what hbbs signs as KxParams.
var KxParamsDomain = []byte("rdkx-params")

var kxSplitContext = []byte("rdkx-spl")

const (
	kxSplitInitiator byte = 1
	kxSplitResponder byte = 2
)

// ErrHandshake is wrapped by every handshake failure.
var ErrHandshake = errors.New("secure handshake failed")

func handshakeErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrHandshake, fmt.Sprintf(format, a...))
}

// KxVersionFor is the version to run against a side that advertised v.
func KxVersionFor(advertised uint32) uint32 {
	return min(advertised, KxVersionLatest)
}

// ParseServerKey decodes the server's public key (base64 Ed25519, the
// contents of id_ed25519.pub).
func ParseServerKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("server key is not valid base64")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("server key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// SignOpen opens a NaCl crypto_sign combined message (signature || message).
func SignOpen(signed []byte, pk ed25519.PublicKey) ([]byte, bool) {
	if len(signed) < ed25519.SignatureSize {
		return nil, false
	}
	sig, msg := signed[:ed25519.SignatureSize], signed[ed25519.SignatureSize:]
	if !ed25519.Verify(pk, msg, sig) {
		return nil, false
	}
	return msg, true
}

// SignedIdPk is an opened, verified IdPk.
type SignedIdPk struct {
	ID        string
	PK        []byte
	KxVersion uint32
}

// OpenIdPk verifies a signed IdPk and checks that it names expectedID.
func OpenIdPk(signed []byte, signer ed25519.PublicKey, expectedID string) (*SignedIdPk, error) {
	msg, ok := SignOpen(signed, signer)
	if !ok {
		return nil, handshakeErr("signature verification failed")
	}
	var idpk pb.IdPk
	if err := proto.Unmarshal(msg, &idpk); err != nil {
		return nil, handshakeErr("malformed signed identity")
	}
	if idpk.GetId() != expectedID {
		return nil, handshakeErr("signed identity is for %q, expected %q", idpk.GetId(), expectedID)
	}
	return &SignedIdPk{ID: idpk.GetId(), PK: idpk.GetPk(), KxVersion: idpk.GetKxVersion()}, nil
}

// PeerLongTermKey verifies hbbs' signature over the peer's long-term Ed25519 key.
func PeerLongTermKey(signedByServer []byte, server ed25519.PublicKey, peerID string) (ed25519.PublicKey, error) {
	idpk, err := OpenIdPk(signedByServer, server, peerID)
	if err != nil {
		return nil, err
	}
	if len(idpk.PK) != ed25519.PublicKeySize {
		return nil, handshakeErr("peer key has wrong length")
	}
	return ed25519.PublicKey(idpk.PK), nil
}

// PeerSessionKey verifies the peer's SignedId with its long-term key and
// returns its ephemeral Curve25519 key and the key exchange version it speaks.
func PeerSessionKey(signedID []byte, longTerm ed25519.PublicKey, peerID string) (*[32]byte, uint32, error) {
	idpk, err := OpenIdPk(signedID, longTerm, peerID)
	if err != nil {
		return nil, 0, err
	}
	if len(idpk.PK) != 32 {
		return nil, 0, handshakeErr("peer session key has wrong length")
	}
	var k [32]byte
	copy(k[:], idpk.PK)
	return &k, idpk.KxVersion, nil
}

// KeyExchange is our half of a key exchange: a fresh symmetric key sealed to
// the other side's ephemeral key.
type KeyExchange struct {
	OurPublic [32]byte // PublicKey.asymmetric_value / KeyExchange.keys[0]
	Sealed    []byte   // PublicKey.symmetric_value / KeyExchange.keys[1]
	Key       [32]byte
}

// NewKeyExchange seals a random symmetric key to their Curve25519 key.
func NewKeyExchange(their *[32]byte) (*KeyExchange, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kx := &KeyExchange{OurPublic: *pub}
	if _, err := rand.Read(kx.Key[:]); err != nil {
		return nil, err
	}
	var nonce [24]byte
	kx.Sealed = box.Seal(nil, kx.Key[:], &nonce, their, priv)
	clear(priv[:])
	return kx, nil
}

// Transcript is what both sides saw during the key exchange (version 1).
type Transcript struct {
	InitiatorPK []byte // the side that sent the sealed key
	ResponderPK []byte // the key it was sealed to, as signed
	Advertised  uint32
	Picked      uint32
}

// Cipher is the per-direction secretbox stream cipher. Nonces are the
// little-endian message counter, incremented before each message.
type Cipher struct {
	send, recv       [32]byte
	sendSeq, recvSeq uint64
}

// NewCipher returns the stream cipher for the version in t.Picked; initiator
// is the side that sent the sealed key (always us, the controlling side).
func NewCipher(key [32]byte, initiator bool, t Transcript) (*Cipher, error) {
	switch t.Picked {
	case 0:
		return &Cipher{send: key, recv: key}, nil
	case 1:
		ini, err := deriveSubkey(key, kxSplitInitiator, t)
		if err != nil {
			return nil, err
		}
		res, err := deriveSubkey(key, kxSplitResponder, t)
		if err != nil {
			return nil, err
		}
		if initiator {
			return &Cipher{send: ini, recv: res}, nil
		}
		return &Cipher{send: res, recv: ini}, nil
	default:
		return nil, handshakeErr("unsupported key exchange version %d", t.Picked)
	}
}

func deriveSubkey(key [32]byte, direction byte, t Transcript) ([32]byte, error) {
	var out [32]byte
	if len(t.InitiatorPK) != 32 || len(t.ResponderPK) != 32 {
		return out, handshakeErr("key exchange transcript has a public key of the wrong length")
	}
	h, err := blake2b.New(32, key[:])
	if err != nil {
		return out, err
	}
	var v [4]byte
	h.Write(kxSplitContext)
	h.Write([]byte{direction})
	binary.LittleEndian.PutUint32(v[:], t.Advertised)
	h.Write(v[:])
	binary.LittleEndian.PutUint32(v[:], t.Picked)
	h.Write(v[:])
	h.Write(t.InitiatorPK)
	h.Write(t.ResponderPK)
	copy(out[:], h.Sum(nil))
	return out, nil
}

func nonce(seq uint64) *[24]byte {
	var n [24]byte
	binary.LittleEndian.PutUint64(n[:], seq)
	return &n
}

// Seal encrypts one message.
func (c *Cipher) Seal(plain []byte) []byte {
	c.sendSeq++
	return secretbox.Seal(nil, plain, nonce(c.sendSeq), &c.send)
}

// Open decrypts one message. Frames of 0 or 1 byte are never encrypted
// (keep-alives) and pass through unchanged.
func (c *Cipher) Open(sealed []byte) ([]byte, error) {
	if len(sealed) <= 1 {
		return sealed, nil
	}
	c.recvSeq++
	plain, ok := secretbox.Open(nil, sealed, nonce(c.recvSeq), &c.recv)
	if !ok {
		return nil, fmt.Errorf("decryption failed at message %d", c.recvSeq)
	}
	return plain, nil
}

// Destroy wipes the keys.
func (c *Cipher) Destroy() {
	clear(c.send[:])
	clear(c.recv[:])
}

// SaltedHash is what a peer stores for "remember password":
// SHA256(password || salt). Password-equivalent for that peer.
func SaltedHash(password, salt string) []byte {
	h := sha256.Sum256([]byte(password + salt))
	return h[:]
}

// LoginProof answers a challenge: SHA256(SHA256(password || salt) || challenge).
func LoginProof(saltedHash []byte, challenge string) []byte {
	h := sha256.New()
	h.Write(saltedHash)
	h.Write([]byte(challenge))
	return h.Sum(nil)
}
