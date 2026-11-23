// Package peer opens an authenticated, encrypted link to a RustDesk peer:
// rendezvous, relay, the key exchange and the login dialogue (password,
// remembered hash, 2FA, approval at the device). What runs after login is up
// to the caller.
package peer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/bropines/rdcli/internal/crypto"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/rendezvous"
	"github.com/bropines/rdcli/internal/wire"
)

// ClientVersion is announced to peers, which enable features by version.
const ClientVersion = "1.4.3"

// Login errors peers send (hbb_common / client.rs).
const (
	msgPasswordEmpty    = "Empty Password"
	msgPasswordWrong    = "Wrong Password"
	msg2FARequired      = "2FA Required"
	msg2FAWrong         = "Wrong 2FA Code"
	msgNoPasswordAccess = "No Password Access"
)

// Code classifies a session failure.
type Code string

const (
	CodeHandshake           Code = "handshake"
	CodeUnverifiedPeer      Code = "unverified-peer"
	CodeLogin               Code = "login"
	CodeWrongPassword       Code = "wrong-password"
	CodeApprovalUnavailable Code = "approval-unavailable"
	CodeApprovalTimeout     Code = "approval-timeout"
	CodePermissionDenied    Code = "permission-denied"
	CodeRemoteClosed        Code = "remote-closed"
	CodeNetwork             Code = "network"
	CodeCancelled           Code = "cancelled"
)

// Error is a session failure.
type Error struct {
	Code Code
	Msg  string
	Err  error // the transport error underneath, if any
}

func (e *Error) Error() string { return e.Msg }

// Unwrap exposes the transport error (io.EOF for a clean close).
func (e *Error) Unwrap() error { return e.Err }

func fail(code Code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Prompter asks the user for secrets during login.
type Prompter interface {
	// Password returns the device password; wrong is set after a refusal.
	Password(wrong bool) (string, error)
	// TwoFactor returns a 2FA code; wrong is set after a refusal.
	TwoFactor(wrong bool) (string, error)
	// Status reports progress ("waiting for approval at the device").
	Status(msg string)
}

// Options for Connect.
type Options struct {
	Server   rendezvous.Server
	PeerID   string
	ConnType pb.ConnType
	// Login fills the session-kind specific LoginRequest fields (union,
	// option, os_login). Called for every login attempt.
	Login func(*pb.LoginRequest)
	// Password is tried first when set (from a flag, env or stdin).
	Password string
	// RememberedHash is SHA256(password || salt) from an earlier login.
	RememberedHash []byte
	// RequestApproval sends no password at all and waits for the person at
	// the device to accept.
	RequestApproval bool
	// ApprovalTimeout bounds the wait for approval (default 2 minutes).
	ApprovalTimeout time.Duration
	Prompter        Prompter
	MyID            string
	MyName          string
	MyPlatform      string
	Version         string
	// LoginErrorCode maps a refusal the dialogue cannot handle to a code.
	LoginErrorCode func(msg string) Code
	// Debugf, when set, receives protocol traces.
	Debugf func(format string, a ...any)
}

// Session is a logged-in link.
type Session struct {
	PeerID    string
	PeerInfo  *pb.PeerInfo
	KxVersion uint32
	// Hash is the salted password hash that worked (nil for approval logins).
	Hash []byte
	// Relay is the relay address the link goes through.
	Relay string

	conn      wire.Conn
	cipher    *crypto.Cipher
	wmu       sync.Mutex
	raw       atomic.Bool
	closed    atomic.Bool
	lastSend  atomic.Int64
	debugf    func(string, ...any)
	sessionID uint64
}

var nonDigitSpace = regexp.MustCompile(`\s+`)

// NormalizeID strips the spaces RustDesk shows in ids ("123 456 789").
func NormalizeID(id string) string { return nonDigitSpace.ReplaceAllString(id, "") }

func (o *Options) debug(format string, a ...any) {
	if o.Debugf != nil {
		o.Debugf(format, a...)
	}
}

// Connect runs rendezvous, relay, key exchange and login.
func Connect(ctx context.Context, o Options) (*Session, error) {
	o.PeerID = NormalizeID(o.PeerID)
	if o.PeerID == "" {
		return nil, fail(CodeLogin, "peer id is empty")
	}
	if o.Version == "" {
		o.Version = ClientVersion
	}
	serverKey, err := crypto.ParseServerKey(o.Server.Key)
	if err != nil {
		return nil, err
	}
	o.debug("rendezvous with %s for %s", wire.Redact(o.Server.IDServer), o.PeerID)
	ticket, err := rendezvous.RequestRelay(ctx, rendezvous.Request{
		Server: o.Server, PeerID: o.PeerID, ConnType: o.ConnType, Version: o.Version,
	})
	if err != nil {
		return nil, err
	}
	if len(ticket.SignedPeerKey) == 0 {
		return nil, fail(CodeUnverifiedPeer, "the server did not vouch for the remote device's key; refusing an unauthenticated connection")
	}
	longTerm, err := crypto.PeerLongTermKey(ticket.SignedPeerKey, serverKey, o.PeerID)
	if err != nil {
		return nil, err
	}
	relayAddr := rendezvous.RelayAddress(o.Server, ticket)
	o.debug("joining relay %s (peer %s)", wire.Redact(relayAddr), ticket.PeerVersion)
	conn, err := rendezvous.JoinRelay(ctx, o.Server, ticket, o.PeerID, o.ConnType)
	if err != nil {
		return nil, err
	}
	s := &Session{PeerID: o.PeerID, conn: conn, Relay: relayAddr, debugf: o.Debugf}
	s.sessionID = randomSessionID()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := s.handshake(longTerm, o.PeerID); err != nil {
		conn.Close()
		return nil, wrapCtx(ctx, err)
	}
	if err := s.login(ctx, &o); err != nil {
		s.Close("")
		return nil, wrapCtx(ctx, err)
	}
	return s, nil
}

func wrapCtx(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fail(CodeCancelled, "cancelled")
	}
	return err
}

func randomSessionID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) & 0x7fff_ffff_ffff_ffff
}

func (s *Session) handshake(longTerm []byte, peerID string) error {
	s.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer s.conn.SetReadDeadline(time.Time{})
	var first pb.Message
	for {
		b, err := s.conn.Recv()
		if err != nil {
			return fail(CodeNetwork, "the remote device did not connect to the relay: %v", err)
		}
		if len(b) == 0 {
			continue
		}
		if proto.Unmarshal(b, &first) != nil {
			return fail(CodeHandshake, "the remote device sent a malformed message")
		}
		break
	}
	sid, ok := first.Union.(*pb.Message_SignedId)
	if !ok {
		return fail(CodeHandshake, "the remote device did not identify itself")
	}
	box, advertised, err := crypto.PeerSessionKey(sid.SignedId.GetId(), longTerm, peerID)
	if err != nil {
		return err
	}
	kx, err := crypto.NewKeyExchange(box)
	if err != nil {
		return err
	}
	picked := crypto.KxVersionFor(advertised)
	out, _ := proto.Marshal(&pb.Message{Union: &pb.Message_PublicKey{PublicKey: &pb.PublicKey{
		AsymmetricValue: kx.OurPublic[:],
		SymmetricValue:  kx.Sealed,
		KxVersion:       picked,
	}}})
	if err := s.conn.Send(out); err != nil {
		return fail(CodeNetwork, "relay connection failed: %v", err)
	}
	c, err := crypto.NewCipher(kx.Key, true, crypto.Transcript{
		InitiatorPK: kx.OurPublic[:], ResponderPK: box[:], Advertised: advertised, Picked: picked,
	})
	if err != nil {
		return err
	}
	s.cipher = c
	s.KxVersion = picked
	s.debugf2("key exchange v%d (peer advertised v%d)", picked, advertised)
	return nil
}

func (s *Session) debugf2(format string, a ...any) {
	if s.debugf != nil {
		s.debugf(format, a...)
	}
}

// keepAlive sends empty frames (never encrypted, ignored by peers) while the
// dialogue waits on a person, so the relay does not drop an idle link.
func (s *Session) keepAlive(stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.wmu.Lock()
			s.conn.Send(nil)
			s.wmu.Unlock()
		}
	}
}

func (s *Session) login(ctx context.Context, o *Options) error {
	stopKA := make(chan struct{})
	defer close(stopKA)
	go s.keepAlive(stopKA)

	var salt, challenge string
	triedPassword, triedRemembered := false, false
	approvalDeadline := time.Time{}
	approvalTimeout := o.ApprovalTimeout
	if approvalTimeout <= 0 {
		approvalTimeout = 2 * time.Minute
	}
	sendLogin := func(hash []byte) error {
		lr := &pb.LoginRequest{
			Username:   o.PeerID,
			MyId:       o.MyID,
			MyName:     o.MyName,
			MyPlatform: o.MyPlatform,
			Version:    o.Version,
			SessionId:  s.sessionID,
		}
		if o.Login != nil {
			o.Login(lr)
		}
		if hash != nil && !o.RequestApproval {
			lr.Password = crypto.LoginProof(hash, challenge)
		}
		return s.Send(&pb.Message{Union: &pb.Message_LoginRequest{LoginRequest: lr}})
	}
	askPassword := func(wrong bool) error {
		if o.Prompter == nil {
			return fail(CodeWrongPassword, "the device needs a password")
		}
		pw, err := o.Prompter.Password(wrong)
		if err != nil {
			return fail(CodeCancelled, "%v", err)
		}
		s.Hash = crypto.SaltedHash(pw, salt)
		return sendLogin(s.Hash)
	}
	startApproval := func() {
		if approvalDeadline.IsZero() {
			approvalDeadline = time.Now().Add(approvalTimeout)
		}
		if o.Prompter != nil {
			o.Prompter.Status("waiting for the person at the device to accept the connection...")
		}
	}

	for {
		deadline := time.Now().Add(30 * time.Second)
		if !approvalDeadline.IsZero() {
			deadline = approvalDeadline
		}
		s.conn.SetReadDeadline(deadline)
		msg, err := s.recvRaw()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if !approvalDeadline.IsZero() {
					s.Send(closeReason("timeout"))
					return fail(CodeApprovalTimeout, "nobody accepted the connection in time")
				}
				return fail(CodeNetwork, "the remote device stopped answering")
			}
			if ctx.Err() != nil {
				return fail(CodeCancelled, "cancelled")
			}
			if !approvalDeadline.IsZero() {
				return fail(CodeRemoteClosed, "the connection was not accepted (%v)", err)
			}
			return fail(CodeNetwork, "connection lost: %v", err)
		}
		if msg == nil {
			continue
		}
		switch u := msg.Union.(type) {
		case *pb.Message_Hash:
			salt, challenge = u.Hash.GetSalt(), u.Hash.GetChallenge()
			switch {
			case o.RequestApproval:
				s.Hash = nil
				if err := sendLogin(nil); err != nil {
					return fail(CodeNetwork, "%v", err)
				}
				startApproval()
			case len(o.RememberedHash) > 0 && !triedRemembered:
				triedRemembered = true
				s.Hash = append([]byte(nil), o.RememberedHash...)
				if err := sendLogin(s.Hash); err != nil {
					return fail(CodeNetwork, "%v", err)
				}
			case o.Password != "" && !triedPassword:
				triedPassword = true
				s.Hash = crypto.SaltedHash(o.Password, salt)
				if err := sendLogin(s.Hash); err != nil {
					return fail(CodeNetwork, "%v", err)
				}
			default:
				if err := askPassword(false); err != nil {
					return err
				}
			}
		case *pb.Message_LoginResponse:
			switch r := u.LoginResponse.Union.(type) {
			case *pb.LoginResponse_PeerInfo:
				s.PeerInfo = r.PeerInfo
				s.conn.SetReadDeadline(time.Time{})
				return nil
			case *pb.LoginResponse_Error:
				e := r.Error
				o.debug("login error %q", e)
				switch e {
				case msgPasswordEmpty, msgPasswordWrong:
					if o.RequestApproval {
						s.Send(closeReason("approval unavailable"))
						return fail(CodeApprovalUnavailable, "the device accepts password logins only (%s)", e)
					}
					if e == msgPasswordWrong {
						s.Hash = nil
						// A stale remembered hash: the device sends Hash
						// only once, so the known password goes now.
						if o.Password != "" && !triedPassword {
							triedPassword = true
							s.Hash = crypto.SaltedHash(o.Password, salt)
							if err := sendLogin(s.Hash); err != nil {
								return fail(CodeNetwork, "%v", err)
							}
							continue
						}
						if o.Prompter == nil || !isTerminalPrompter(o.Prompter) {
							return fail(CodeWrongPassword, "wrong password")
						}
					}
					if err := askPassword(e == msgPasswordWrong); err != nil {
						return err
					}
				case msg2FARequired, msg2FAWrong:
					approvalDeadline = time.Time{}
					if o.Prompter == nil {
						return fail(CodeLogin, "the device asks for a 2FA code")
					}
					code, err := o.Prompter.TwoFactor(e == msg2FAWrong)
					if err != nil {
						return fail(CodeCancelled, "%v", err)
					}
					if err := s.Send(&pb.Message{Union: &pb.Message_Auth_2Fa{Auth_2Fa: &pb.Auth2FA{Code: strings.TrimSpace(code)}}}); err != nil {
						return fail(CodeNetwork, "%v", err)
					}
				case msgNoPasswordAccess:
					startApproval()
				default:
					code := CodeLogin
					if o.LoginErrorCode != nil {
						code = o.LoginErrorCode(e)
					}
					return fail(code, "%s", e)
				}
			}
		case *pb.Message_TestDelay:
			if !u.TestDelay.GetFromClient() {
				s.Send(msg)
			}
		case *pb.Message_Misc:
			if r, ok := u.Misc.Union.(*pb.Misc_CloseReason); ok {
				reason := r.CloseReason
				if reason == "" {
					reason = "closed by the remote side"
				}
				return fail(CodeRemoteClosed, "%s", reason)
			}
		case *pb.Message_MessageBox:
			if o.Prompter != nil && u.MessageBox.GetText() != "" {
				o.Prompter.Status(u.MessageBox.GetTitle() + ": " + u.MessageBox.GetText())
			}
		}
	}
}

// interactive prompters may retry a wrong password; scripted ones may not.
type retryable interface{ CanRetry() bool }

func isTerminalPrompter(p Prompter) bool {
	r, ok := p.(retryable)
	return !ok || r.CanRetry()
}

func closeReason(r string) *pb.Message {
	return &pb.Message{Union: &pb.Message_Misc{Misc: &pb.Misc{Union: &pb.Misc_CloseReason{CloseReason: r}}}}
}

// recvRaw reads, decrypts and parses one message; nil for keep-alives.
func (s *Session) recvRaw() (*pb.Message, error) {
	b, err := s.conn.Recv()
	if err != nil {
		return nil, err
	}
	if b, err = s.cipher.Open(b); err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var m pb.Message
	if err := proto.Unmarshal(b, &m); err != nil {
		return nil, nil
	}
	return &m, nil
}

// Send encrypts and sends one message.
func (s *Session) Send(m *pb.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	if s.raw.Load() {
		return errors.New("session is in raw mode")
	}
	s.lastSend.Store(time.Now().UnixNano())
	return s.conn.Send(s.cipher.Seal(b))
}

// Recv returns the next message after login. It answers the peer's latency
// probes itself and turns a close reason into an error.
func (s *Session) Recv() (*pb.Message, error) {
	for {
		m, err := s.recvRaw()
		if err != nil {
			if s.closed.Load() {
				return nil, net.ErrClosed
			}
			return nil, &Error{Code: CodeNetwork, Msg: "connection lost: " + err.Error(), Err: err}
		}
		if m == nil {
			continue
		}
		switch u := m.Union.(type) {
		case *pb.Message_TestDelay:
			if !u.TestDelay.GetFromClient() {
				s.Send(m)
			}
			continue
		case *pb.Message_Misc:
			if r, ok := u.Misc.Union.(*pb.Misc_CloseReason); ok {
				reason := r.CloseReason
				if reason == "" {
					reason = "closed by the remote side"
				}
				return nil, fail(CodeRemoteClosed, "%s", reason)
			}
		}
		return m, nil
	}
}

// KeepAlive sends a latency probe (echoed by the peer) whenever nothing was
// sent for every/2, until ctx ends. A relay drops a link that carries
// nothing (hbbr after 30 s); an idle shell or tunnel is such a link.
func (s *Session) KeepAlive(ctx context.Context, every time.Duration) {
	tick := max(every/2, time.Second)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.closed.Load() || s.raw.Load() {
				return
			}
			if time.Since(time.Unix(0, s.lastSend.Load())) < tick {
				continue
			}
			s.Send(&pb.Message{Union: &pb.Message_TestDelay{TestDelay: &pb.TestDelay{Time: time.Now().UnixMilli(), FromClient: true}}})
		}
	}
}

// SetRaw ends message framing and encryption: what legacy port forwarding
// does after login. Everything after this is plain bytes on the relay.
func (s *Session) SetRaw() {
	s.wmu.Lock()
	s.raw.Store(true)
	s.conn.SetRaw()
	s.wmu.Unlock()
}

// SendRaw writes bytes in raw mode.
func (s *Session) SendRaw(b []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.conn.Send(b)
}

// RecvRaw reads bytes in raw mode.
func (s *Session) RecvRaw() ([]byte, error) { return s.conn.Recv() }

// SetWriteDeadline bounds the next writes.
func (s *Session) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// Close ends the link, telling the peer why when reason is set.
func (s *Session) Close(reason string) {
	if s.closed.Load() {
		return
	}
	if reason != "" && !s.raw.Load() {
		s.conn.SetWriteDeadline(time.Now().Add(time.Second))
		s.Send(closeReason(reason))
	}
	s.closed.Store(true)
	s.conn.Close()
	if s.cipher != nil {
		s.wmu.Lock()
		s.cipher.Destroy()
		s.wmu.Unlock()
	}
}

// Features reports what the peer announced in PeerInfo.
func (s *Session) Features() *pb.Features {
	if s.PeerInfo == nil {
		return nil
	}
	return s.PeerInfo.GetFeatures()
}
