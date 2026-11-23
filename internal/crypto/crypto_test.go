package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"

	"github.com/bropines/rdcli/internal/pb"
)

func fill(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// The same fixed bytes hbb_common pins (tcp.rs test_wire_vectors).
func TestWireVectors(t *testing.T) {
	var key [32]byte
	copy(key[:], fill(0x11))
	c, _ := NewCipher(key, true, Transcript{})
	if got := hex.EncodeToString(c.Seal([]byte("hello"))); got != "3b768f827fdcc4af555b9e42533be6611e2c333481" {
		t.Fatalf("v0 frame %s", got)
	}
	tr := Transcript{InitiatorPK: fill(0x22), ResponderPK: fill(0x33), Advertised: 1, Picked: 1}
	c, err := NewCipher(key, true, tr)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(c.send[:]) != "c189ec6e1935c0751cfc85a0f075405cae507d7925bb19687caf56cbb54e0ecf" ||
		hex.EncodeToString(c.recv[:]) != "8a62648e9195cb10ea900c0a24d2a166c1e982347a2dc6833c3e756bf5715d36" {
		t.Fatalf("v1 subkeys %x %x", c.send, c.recv)
	}
	tr.Advertised = 3
	c, _ = NewCipher(key, true, tr)
	if hex.EncodeToString(c.send[:]) != "25b0778ae600f9731c7fa457d1cc5d40071b0aa3d34c90b53e1d5344b0e7123a" ||
		hex.EncodeToString(c.recv[:]) != "5bbde0ac6a708d4cd1ff807125d79cb6030bde62f7a66b6cc1a79e31bd657756" {
		t.Fatalf("v1 subkeys (advertised 3) %x %x", c.send, c.recv)
	}
}

func TestSplitRoundTrip(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])
	tr := Transcript{InitiatorPK: fill(1), ResponderPK: fill(2), Advertised: 1, Picked: 1}
	a, _ := NewCipher(key, true, tr)
	b, _ := NewCipher(key, false, tr)
	for i := 0; i < 3; i++ {
		got, err := b.Open(a.Seal([]byte("ping")))
		if err != nil || string(got) != "ping" {
			t.Fatalf("a->b %q %v", got, err)
		}
		got, err = a.Open(b.Seal([]byte("pong")))
		if err != nil || string(got) != "pong" {
			t.Fatalf("b->a %q %v", got, err)
		}
	}
	same, _ := NewCipher(key, true, tr)
	if _, err := same.Open(a.Seal([]byte("x"))); err == nil {
		t.Fatal("two initiators must not understand each other")
	}
	if _, err := NewCipher(key, true, Transcript{Picked: 2}); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestKeepAlivesPassThrough(t *testing.T) {
	c, _ := NewCipher([32]byte{}, true, Transcript{})
	for _, b := range [][]byte{{}, {0}} {
		got, err := c.Open(b)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatal("keep-alive was decrypted")
		}
	}
	if c.recvSeq != 0 {
		t.Fatal("keep-alive advanced the counter")
	}
}

func signIdPk(t *testing.T, sk ed25519.PrivateKey, id string, pk []byte, kx uint32) []byte {
	msg, err := proto.Marshal(&pb.IdPk{Id: id, Pk: pk, KxVersion: kx})
	if err != nil {
		t.Fatal(err)
	}
	return append(ed25519.Sign(sk, msg), msg...)
}

func TestHandshakeChain(t *testing.T) {
	serverPub, serverSk, _ := ed25519.GenerateKey(rand.Reader)
	peerPub, peerSk, _ := ed25519.GenerateKey(rand.Reader)
	ephPub, ephSk, _ := box.GenerateKey(rand.Reader)

	lt, err := PeerLongTermKey(signIdPk(t, serverSk, "123", peerPub, 0), serverPub, "123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PeerLongTermKey(signIdPk(t, serverSk, "123", peerPub, 0), serverPub, "456"); err == nil {
		t.Fatal("id mismatch accepted")
	}
	if _, err := PeerLongTermKey(signIdPk(t, peerSk, "123", peerPub, 0), serverPub, "123"); err == nil {
		t.Fatal("wrong signer accepted")
	}
	session, kxv, err := PeerSessionKey(signIdPk(t, peerSk, "123", ephPub[:], 1), lt, "123")
	if err != nil || kxv != 1 {
		t.Fatal(err, kxv)
	}
	kx, err := NewKeyExchange(session)
	if err != nil {
		t.Fatal(err)
	}
	var n [24]byte
	opened, ok := box.Open(nil, kx.Sealed, &n, &kx.OurPublic, ephSk)
	if !ok || !bytes.Equal(opened, kx.Key[:]) {
		t.Fatal("peer cannot open the sealed key")
	}
}

func TestLoginProof(t *testing.T) {
	h := SaltedHash("pw", "salt")
	p := LoginProof(h, "ch")
	if len(h) != 32 || len(p) != 32 || bytes.Equal(h, p) {
		t.Fatal("bad hashes")
	}
	if hex.EncodeToString(SaltedHash("", "")) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatal("salted hash is not sha256(password||salt)")
	}
}

func TestParseServerKey(t *testing.T) {
	if _, err := ParseServerKey("OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseServerKey("abc"); err == nil {
		t.Fatal("short key accepted")
	}
}
