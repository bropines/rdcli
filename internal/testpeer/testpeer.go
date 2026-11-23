// Package testpeer is an in-process RustDesk server (hbbs + hbbr) and a
// controlled peer, for end-to-end tests of rdcli. It follows the wire
// behaviour of hbbs/hbbr and RustDesk's server/connection.rs closely enough
// to exercise the real code paths: the signed key exchange with hbbs (v0 and
// v1), the relay, the peer handshake, the login dialogue, terminals and port
// forwarding (multiplexed and legacy).
package testpeer

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	"google.golang.org/protobuf/proto"

	"github.com/bropines/rdcli/internal/crypto"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/wire"
)

// Options configure the fake server and peer.
type Options struct {
	PeerID       string
	Password     string
	ServerKxV1   bool   // hbbs advertises key exchange v1 (signed params)
	PeerKxV1     bool   // the peer advertises key exchange v1
	NoServerKX   bool   // hbbs sends no KeyExchange (a server without a key)
	RequireTok   string // hbbs refuses a PunchHoleRequest without this token
	Mux          bool   // the peer announces port_forward_mux
	Offline      bool   // hbbs answers OFFLINE
	ClickOnly    bool   // the peer answers "No Password Access", accepts after ApproveAfter
	ApproveAfter time.Duration
	TwoFA        string // the peer asks for this 2FA code after the password
	Platform     string
	SameLAN      bool // hbbs answers with the peer's LAN address (one public IP)
}

// Server is the fake hbbs + hbbr + peer.
type Server struct {
	t       testing.TB
	o       Options
	Key     string // server public key (base64)
	sk      ed25519.PrivateKey
	peerPK  ed25519.PublicKey
	peerSK  ed25519.PrivateKey
	hbbs    net.Listener
	hbbr    net.Listener
	mu      sync.Mutex
	waiting map[string]net.Conn
	pairs   map[string]chan net.Conn
	// Logins counts successful peer logins.
	Logins int
	// ClientRelays counts client-initiated relay requests.
	ClientRelays int
	// Targets records forward targets opened on the device.
	Targets []string
	// KxVersions records the picked peer key exchange versions.
	KxVersions []uint32
	// ServerKxVersions records the picked hbbs key exchange versions.
	ServerKxVersions []uint32
}

// Start runs the fake server on loopback.
func Start(t testing.TB, o Options) *Server {
	if o.PeerID == "" {
		o.PeerID = "123456789"
	}
	if o.Platform == "" {
		o.Platform = "Linux"
	}
	pub, sk, _ := ed25519.GenerateKey(rand.Reader)
	ppub, psk, _ := ed25519.GenerateKey(rand.Reader)
	s := &Server{t: t, o: o, Key: base64.StdEncoding.EncodeToString(pub), sk: sk, peerPK: ppub, peerSK: psk,
		waiting: map[string]net.Conn{}, pairs: map[string]chan net.Conn{}}
	var err error
	if s.hbbs, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if s.hbbr, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go s.acceptLoop(s.hbbs, s.serveHbbs)
	go s.acceptLoop(s.hbbr, s.serveHbbr)
	t.Cleanup(func() { s.hbbs.Close(); s.hbbr.Close() })
	return s
}

// IDServer is the hbbs address.
func (s *Server) IDServer() string { return s.hbbs.Addr().String() }

func (s *Server) acceptLoop(ln net.Listener, fn func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go fn(c)
	}
}

func signed(sk ed25519.PrivateKey, msg []byte) []byte {
	return append(ed25519.Sign(sk, msg), msg...)
}

func (s *Server) signIdPk(sk ed25519.PrivateKey, id string, pk []byte, kx uint32) []byte {
	b, _ := proto.Marshal(&pb.IdPk{Id: id, Pk: pk, KxVersion: kx})
	return signed(sk, b)
}

type rconn struct {
	c      *wire.TCP
	cipher *crypto.Cipher
}

func (r *rconn) send(m *pb.RendezvousMessage) error {
	b, _ := proto.Marshal(m)
	if r.cipher != nil {
		b = r.cipher.Seal(b)
	}
	return r.c.Send(b)
}

func (r *rconn) recv() (*pb.RendezvousMessage, error) {
	b, err := r.c.Recv()
	if err != nil {
		return nil, err
	}
	if r.cipher != nil {
		if b, err = r.cipher.Open(b); err != nil {
			return nil, err
		}
	}
	var m pb.RendezvousMessage
	return &m, proto.Unmarshal(b, &m)
}

func (s *Server) serveHbbs(c net.Conn) {
	defer c.Close()
	r := &rconn{c: wire.NewTCP(c)}
	var serverPK [32]byte
	var serverSK *[32]byte
	advertised := uint32(0)
	if !s.o.NoServerKX {
		pub, priv, _ := box.GenerateKey(rand.Reader)
		serverSK = priv
		serverPK = *pub
		ex := &pb.KeyExchange{}
		if s.o.ServerKxV1 {
			advertised = 1
			serverPK[31] |= 0x80
			params, _ := proto.Marshal(&pb.KxParams{Pk: serverPK[:], Version: 1})
			ex.Version = 1
			ex.SignedParams = signed(s.sk, append(append([]byte(nil), crypto.KxParamsDomain...), params...))
		}
		ex.Keys = [][]byte{signed(s.sk, serverPK[:])}
		r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_KeyExchange{KeyExchange: ex}})
	}
	for {
		m, err := r.recv()
		if err != nil {
			return
		}
		switch u := m.Union.(type) {
		case *pb.RendezvousMessage_KeyExchange:
			if serverSK == nil || len(u.KeyExchange.Keys) != 2 {
				return
			}
			var their [32]byte
			copy(their[:], u.KeyExchange.Keys[0])
			var n [24]byte
			key, ok := box.Open(nil, u.KeyExchange.Keys[1], &n, &their, serverSK)
			if !ok {
				s.t.Errorf("hbbs: cannot open the key exchange box")
				return
			}
			picked := uint32(0)
			if advertised > 0 {
				picked = u.KeyExchange.Version
			}
			s.mu.Lock()
			s.ServerKxVersions = append(s.ServerKxVersions, picked)
			s.mu.Unlock()
			var k [32]byte
			copy(k[:], key)
			ci, err := crypto.NewCipher(k, false, crypto.Transcript{InitiatorPK: their[:], ResponderPK: serverPK[:], Advertised: advertised, Picked: picked})
			if err != nil {
				s.t.Errorf("hbbs: %v", err)
				return
			}
			r.cipher = ci
		case *pb.RendezvousMessage_RequestRelay:
			// a client-initiated relay (after a direct-connection answer)
			rr := u.RequestRelay
			if rr.Id != s.o.PeerID || rr.Uuid == "" {
				return
			}
			s.mu.Lock()
			s.ClientRelays++
			s.mu.Unlock()
			go s.runPeer(rr.Uuid, rr.ConnType)
			r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_RelayResponse{RelayResponse: &pb.RelayResponse{
				Uuid: rr.Uuid, RelayServer: rr.RelayServer, Version: "1.5.0",
			}}})
		case *pb.RendezvousMessage_PunchHoleRequest:
			req := u.PunchHoleRequest
			if req.LicenceKey != s.Key {
				r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_PunchHoleResponse{PunchHoleResponse: &pb.PunchHoleResponse{Failure: pb.PunchHoleResponse_LICENSE_MISMATCH}}})
				return
			}
			if s.o.RequireTok != "" && req.Token != s.o.RequireTok {
				r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_PunchHoleResponse{PunchHoleResponse: &pb.PunchHoleResponse{OtherFailure: "Connection failed, please login!"}}})
				return
			}
			if s.o.Offline || req.Id != s.o.PeerID {
				f := pb.PunchHoleResponse_OFFLINE
				if req.Id != s.o.PeerID {
					f = pb.PunchHoleResponse_ID_NOT_EXIST
				}
				r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_PunchHoleResponse{PunchHoleResponse: &pb.PunchHoleResponse{Failure: f}}})
				return
			}
			if s.o.SameLAN {
				// hbbs sent FetchLocalAddr; the peer's LocalAddr comes back
				// as a PunchHoleResponse with its LAN address.
				r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_PunchHoleResponse{PunchHoleResponse: &pb.PunchHoleResponse{
					SocketAddr: []byte{192, 168, 1, 5, 0x52, 0x6c}, Pk: s.signIdPk(s.sk, s.o.PeerID, s.peerPK, 0),
					RelayServer: s.hbbr.Addr().String(), Union: &pb.PunchHoleResponse_IsLocal{IsLocal: true},
				}}})
				continue
			}
			uuid := fmt.Sprintf("u-%d", time.Now().UnixNano())
			go s.runPeer(uuid, req.ConnType)
			r.send(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_RelayResponse{RelayResponse: &pb.RelayResponse{
				Uuid: uuid, RelayServer: s.hbbr.Addr().String(), Version: "1.5.0",
				Union: &pb.RelayResponse_Pk{Pk: s.signIdPk(s.sk, s.o.PeerID, s.peerPK, 0)},
			}}})
		}
	}
}

// serveHbbr pairs two connections by uuid and copies bytes between them.
func (s *Server) serveHbbr(c net.Conn) {
	br := bufio.NewReader(c)
	b, err := wire.ReadFrame(br, 1<<20)
	if err != nil {
		c.Close()
		return
	}
	var m pb.RendezvousMessage
	if proto.Unmarshal(b, &m) != nil || m.GetRequestRelay() == nil {
		c.Close()
		return
	}
	uuid := m.GetRequestRelay().Uuid
	bc := &bufConn{Conn: c, r: br}
	s.mu.Lock()
	other, ok := s.waiting[uuid]
	if !ok {
		s.waiting[uuid] = bc
		s.mu.Unlock()
		return
	}
	delete(s.waiting, uuid)
	s.mu.Unlock()
	go func() { io.Copy(other, bc); other.Close(); bc.Close() }()
	io.Copy(bc, other)
	bc.Close()
	other.Close()
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// --- the controlled peer ---------------------------------------------------

type pconn struct {
	c      *wire.TCP
	cipher *crypto.Cipher
	wmu    sync.Mutex
}

func (p *pconn) send(m *pb.Message) error {
	b, _ := proto.Marshal(m)
	p.wmu.Lock()
	defer p.wmu.Unlock()
	if p.cipher != nil {
		b = p.cipher.Seal(b)
	}
	return p.c.Send(b)
}

func (p *pconn) recv() (*pb.Message, error) {
	for {
		b, err := p.c.Recv()
		if err != nil {
			return nil, err
		}
		if p.cipher != nil {
			if b, err = p.cipher.Open(b); err != nil {
				return nil, err
			}
		}
		if len(b) == 0 {
			continue // keep-alive
		}
		var m pb.Message
		if err := proto.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		return &m, nil
	}
}

func (s *Server) runPeer(uuid string, ct pb.ConnType) {
	c, err := net.Dial("tcp", s.hbbr.Addr().String())
	if err != nil {
		return
	}
	defer c.Close()
	req, _ := proto.Marshal(&pb.RendezvousMessage{Union: &pb.RendezvousMessage_RequestRelay{RequestRelay: &pb.RequestRelay{Uuid: uuid}}})
	tc := wire.NewTCP(c)
	tc.Send(req)
	p := &pconn{c: tc}

	ephPub, ephSK, _ := box.GenerateKey(rand.Reader)
	adv := uint32(0)
	if s.o.PeerKxV1 {
		adv = 1
	}
	p.send(&pb.Message{Union: &pb.Message_SignedId{SignedId: &pb.SignedId{Id: s.signIdPk(s.peerSK, s.o.PeerID, ephPub[:], adv)}}})
	m, err := p.recv()
	if err != nil {
		return
	}
	pk := m.GetPublicKey()
	if pk == nil {
		s.t.Errorf("peer: expected PublicKey, got %T", m.Union)
		return
	}
	var their [32]byte
	copy(their[:], pk.AsymmetricValue)
	var n [24]byte
	key, ok := box.Open(nil, pk.SymmetricValue, &n, &their, ephSK)
	if !ok {
		s.t.Errorf("peer: cannot open the session key")
		return
	}
	picked := pk.KxVersion
	if picked > adv {
		s.t.Errorf("peer: client picked kx v%d above advertised v%d", picked, adv)
		return
	}
	s.mu.Lock()
	s.KxVersions = append(s.KxVersions, picked)
	s.mu.Unlock()
	var k [32]byte
	copy(k[:], key)
	p.cipher, err = crypto.NewCipher(k, false, crypto.Transcript{InitiatorPK: pk.AsymmetricValue, ResponderPK: ephPub[:], Advertised: adv, Picked: picked})
	if err != nil {
		s.t.Errorf("peer: %v", err)
		return
	}
	salt, challenge := "salt-xyz", fmt.Sprintf("ch-%d", time.Now().UnixNano())
	p.send(&pb.Message{Union: &pb.Message_Hash{Hash: &pb.Hash{Salt: salt, Challenge: challenge}}})
	want := crypto.LoginProof(crypto.SaltedHash(s.o.Password, salt), challenge)

	var lr *pb.LoginRequest
	authorized := false
	needCode := s.o.TwoFA != ""
	loginErr := func(e string) {
		p.send(&pb.Message{Union: &pb.Message_LoginResponse{LoginResponse: &pb.LoginResponse{Union: &pb.LoginResponse_Error{Error: e}}}})
	}
	accept := func() {
		authorized = true
		s.mu.Lock()
		s.Logins++
		s.mu.Unlock()
		p.send(&pb.Message{Union: &pb.Message_LoginResponse{LoginResponse: &pb.LoginResponse{Union: &pb.LoginResponse_PeerInfo{PeerInfo: &pb.PeerInfo{
			Username: "alice", Hostname: "box", Platform: s.o.Platform, Version: "1.5.0",
			Features: &pb.Features{Terminal: true, PortForwardMux: s.o.Mux},
		}}}}})
	}
	for !authorized {
		m, err := p.recv()
		if err != nil {
			return
		}
		switch u := m.Union.(type) {
		case *pb.Message_LoginRequest:
			lr = u.LoginRequest
			if s.o.ClickOnly {
				loginErr("No Password Access")
				time.Sleep(s.o.ApproveAfter)
				accept()
				continue
			}
			if len(lr.Password) == 0 {
				continue // the device would show its accept dialog
			}
			if string(lr.Password) != string(want) {
				loginErr("Wrong Password")
				continue
			}
			if needCode {
				loginErr("2FA Required")
				continue
			}
			accept()
		case *pb.Message_Auth_2Fa:
			if u.Auth_2Fa.Code != s.o.TwoFA {
				loginErr("Wrong 2FA Code")
				continue
			}
			accept()
		case *pb.Message_TestDelay:
		}
	}
	switch {
	case ct == pb.ConnType_TERMINAL:
		s.serveTerminal(p)
	case ct == pb.ConnType_PORT_FORWARD:
		pf := lr.GetPortForward()
		if pf == nil {
			return
		}
		target := net.JoinHostPort(pf.Host, fmt.Sprint(pf.Port))
		if pf.Multiplex && s.o.Mux {
			s.serveMux(p, target)
		} else {
			s.serveLegacy(p, tc, target)
		}
	}
}

// serveTerminal: a "shell" that echoes input upper-cased and exits with
// code 3 on "exit\n".
func (s *Server) serveTerminal(p *pconn) {
	var line strings.Builder
	for {
		m, err := p.recv()
		if err != nil {
			return
		}
		a := m.GetTerminalAction()
		if a == nil {
			if td := m.GetTestDelay(); td != nil && td.FromClient {
				p.send(m)
			}
			continue
		}
		switch u := a.Union.(type) {
		case *pb.TerminalAction_Open:
			p.send(&pb.Message{Union: &pb.Message_TerminalResponse{TerminalResponse: &pb.TerminalResponse{Union: &pb.TerminalResponse_Opened{Opened: &pb.TerminalOpened{
				TerminalId: u.Open.TerminalId, Success: true, ServiceId: "svc-1",
			}}}}})
			p.send(termData(u.Open.TerminalId, []byte(fmt.Sprintf("size %dx%d\r\n", u.Open.Cols, u.Open.Rows))))
		case *pb.TerminalAction_Resize:
			p.send(termData(u.Resize.TerminalId, []byte(fmt.Sprintf("resized %dx%d\r\n", u.Resize.Cols, u.Resize.Rows))))
		case *pb.TerminalAction_Data:
			for _, c := range string(u.Data.Data) {
				line.WriteRune(c)
				if c == '\n' {
					if strings.TrimSpace(line.String()) == "exit" {
						p.send(&pb.Message{Union: &pb.Message_TerminalResponse{TerminalResponse: &pb.TerminalResponse{Union: &pb.TerminalResponse_Closed{Closed: &pb.TerminalClosed{TerminalId: u.Data.TerminalId, ExitCode: 3}}}}})
						return
					}
					line.Reset()
				}
			}
			p.send(termData(u.Data.TerminalId, []byte(strings.ToUpper(string(u.Data.Data)))))
		case *pb.TerminalAction_Close:
			p.send(&pb.Message{Union: &pb.Message_TerminalResponse{TerminalResponse: &pb.TerminalResponse{Union: &pb.TerminalResponse_Closed{Closed: &pb.TerminalClosed{TerminalId: u.Close.TerminalId}}}}})
			return
		}
	}
}

func termData(id int32, b []byte) *pb.Message {
	return &pb.Message{Union: &pb.Message_TerminalResponse{TerminalResponse: &pb.TerminalResponse{Union: &pb.TerminalResponse_Data{Data: &pb.TerminalData{TerminalId: id, Data: b}}}}}
}

func (s *Server) serveLegacy(p *pconn, tc *wire.TCP, target string) {
	dst, err := net.Dial("tcp", target)
	if err != nil {
		p.send(&pb.Message{Union: &pb.Message_LoginResponse{LoginResponse: &pb.LoginResponse{Union: &pb.LoginResponse_Error{Error: "Failed to access remote " + target}}}})
		return
	}
	s.mu.Lock()
	s.Targets = append(s.Targets, target)
	s.mu.Unlock()
	defer dst.Close()
	tc.SetRaw()
	go func() {
		for {
			b, err := tc.Recv()
			if len(b) > 0 {
				dst.Write(b)
			}
			if err != nil {
				dst.Close()
				return
			}
		}
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := dst.Read(buf)
		if n > 0 {
			tc.Send(append([]byte(nil), buf[:n]...))
		}
		if err != nil {
			return
		}
	}
}

// serveMux is the controlled side of a multiplexed tunnel, with the same
// windows as port_forward_mux.rs (it enforces our window as well).
func (s *Server) serveMux(p *pconn, loginTarget string) {
	type ch struct {
		conn      net.Conn
		credit    *int64
		remaining int64
		drained   int64
		mu        sync.Mutex
		cond      *sync.Cond
	}
	var mu sync.Mutex
	chans := map[int32]*ch{}
	send := func(u *pb.PortForwardChannel) {
		p.send(&pb.Message{Union: &pb.Message_PortForwardChannel{PortForwardChannel: u}})
	}
	for {
		m, err := p.recv()
		if err != nil {
			mu.Lock()
			for _, c := range chans {
				c.conn.Close()
			}
			mu.Unlock()
			return
		}
		if td := m.GetTestDelay(); td != nil {
			if td.FromClient {
				p.send(m)
			}
			continue
		}
		f := m.GetPortForwardChannel()
		if f == nil {
			continue
		}
		switch u := f.Union.(type) {
		case *pb.PortForwardChannel_Open:
			o := u.Open
			target := net.JoinHostPort(o.Host, fmt.Sprint(o.Port))
			if target != loginTarget {
				send(&pb.PortForwardChannel{Union: &pb.PortForwardChannel_Opened{Opened: &pb.PortForwardOpened{ChannelId: o.ChannelId, Message: "Port forward target not authorized"}}})
				continue
			}
			conn, err := net.Dial("tcp", target)
			if err != nil {
				send(&pb.PortForwardChannel{Union: &pb.PortForwardChannel_Opened{Opened: &pb.PortForwardOpened{ChannelId: o.ChannelId, Message: err.Error()}}})
				continue
			}
			s.mu.Lock()
			s.Targets = append(s.Targets, target)
			s.mu.Unlock()
			credit := int64(max(o.Window, 64*1024))
			c := &ch{conn: conn, credit: &credit, remaining: 256 * 1024}
			c.cond = sync.NewCond(&c.mu)
			mu.Lock()
			chans[o.ChannelId] = c
			mu.Unlock()
			send(&pb.PortForwardChannel{Union: &pb.PortForwardChannel_Opened{Opened: &pb.PortForwardOpened{ChannelId: o.ChannelId, Success: true, Window: 256 * 1024}}})
			id := o.ChannelId
			go func() {
				buf := make([]byte, 64*1024)
				for {
					c.mu.Lock()
					for *c.credit < 64 {
						c.cond.Wait()
					}
					allow := min(int(*c.credit), len(buf))
					c.mu.Unlock()
					n, err := conn.Read(buf[:allow])
					if n > 0 {
						c.mu.Lock()
						*c.credit -= int64(max(n, 64))
						c.mu.Unlock()
						send(&pb.PortForwardChannel{Union: &pb.PortForwardChannel_Data{Data: &pb.PortForwardData{ChannelId: id, Data: append([]byte(nil), buf[:n]...)}}})
					}
					if err != nil {
						mu.Lock()
						_, live := chans[id]
						delete(chans, id)
						mu.Unlock()
						if live {
							send(&pb.PortForwardChannel{Union: &pb.PortForwardChannel_Close{Close: &pb.PortForwardClose{ChannelId: id}}})
						}
						return
					}
				}
			}()
		case *pb.PortForwardChannel_Data:
			mu.Lock()
			c := chans[u.Data.ChannelId]
			mu.Unlock()
			if c == nil {
				continue
			}
			c.remaining -= int64(max(len(u.Data.Data), 64))
			if c.remaining < 0 {
				s.t.Errorf("peer: controller overran the window on channel %d", u.Data.ChannelId)
			}
			c.conn.Write(u.Data.Data)
			// grant back what we drained, in UPDATE_THRESHOLD (128K) steps
			c.drained += int64(max(len(u.Data.Data), 64))
			if c.drained >= 128*1024 {
				c.remaining += c.drained
				send(&pb.PortForwardChannel{Union: &pb.PortForwardChannel_WindowUpdate{WindowUpdate: &pb.PortForwardWindowUpdate{ChannelId: u.Data.ChannelId, Add: uint32(c.drained)}}})
				c.drained = 0
			}
		case *pb.PortForwardChannel_WindowUpdate:
			mu.Lock()
			c := chans[u.WindowUpdate.ChannelId]
			mu.Unlock()
			if c != nil {
				c.mu.Lock()
				*c.credit = min(*c.credit+int64(u.WindowUpdate.Add), 256*1024)
				c.mu.Unlock()
				c.cond.Broadcast()
			}
		case *pb.PortForwardChannel_Close:
			mu.Lock()
			c := chans[u.Close.ChannelId]
			delete(chans, u.Close.ChannelId)
			mu.Unlock()
			if c != nil {
				c.conn.Close()
			}
		}
	}
}

// EchoServer is a TCP echo target on loopback.
func EchoServer(t testing.TB) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// BurstServer is a target that writes n bytes as soon as a client connects,
// then closes, whatever the client is still sending.
func BurstServer(t testing.TB, n int) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.Write(make([]byte, n))
				// Half-close: a full close with unread input sends an RST,
				// which discards our own unsent output on some stacks.
				c.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}
