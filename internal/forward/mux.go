// Package forward tunnels TCP connections through a RustDesk peer: the
// multiplexed tunnel of RustDesk 1.5 (every connection a channel on one
// encrypted link) and the legacy raw pipe (one link per connection, plain
// bytes after login) for older peers.
package forward

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
)

// Flow control constants, fixed on the wire (port_forward_mux.rs).
const (
	InitialWindow   uint32 = 64 * 1024
	MinFrameCharge  uint32 = 64
	ChannelWindow   uint32 = 256 * 1024
	MaxFrame               = 64 * 1024
	UpdateThreshold        = ChannelWindow / 2
	MaxChannels            = 256
	MaxSendCredit          = ChannelWindow
)

// DefaultLinger is how long a channel whose local end stopped sending (EOF)
// waits for more data from the device before closing. A variable for tests.
var DefaultLinger = 10 * time.Second

func effectiveWindow(advertised uint32) uint32 { return max(advertised, InitialWindow) }

func charge(n int) uint32 { return max(uint32(min(n, int(^uint32(0)>>1))), MinFrameCharge) }

// sendCredit is what the peer lets us have in flight on a channel.
type sendCredit struct {
	mu     sync.Mutex
	cond   *sync.Cond
	credit uint32
	closed bool
}

func newSendCredit(initial uint32) *sendCredit {
	c := &sendCredit{credit: min(initial, MaxSendCredit)}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// take waits for at least MinFrameCharge of credit and takes up to max.
func (c *sendCredit) take(max int) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.credit < MinFrameCharge && !c.closed {
		c.cond.Wait()
	}
	if c.closed {
		return 0, false
	}
	n := min(int(c.credit), max)
	c.credit -= uint32(n)
	return n, true
}

func (c *sendCredit) add(n uint32) {
	c.mu.Lock()
	c.credit = min(c.credit+min(n, MaxSendCredit), MaxSendCredit)
	c.mu.Unlock()
	c.cond.Broadcast()
}

func (c *sendCredit) raiseInitial(total uint32) {
	if extra := effectiveWindow(total) - InitialWindow; extra > 0 {
		c.add(extra)
	}
}

func (c *sendCredit) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cond.Broadcast()
}

// recvWindow accounts what the peer may still send us.
type recvWindow struct {
	mu        sync.Mutex
	remaining uint32
	drained   uint32
}

func (w *recvWindow) accept(n int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := charge(n)
	if c > w.remaining {
		return false
	}
	w.remaining -= c
	return true
}

// drain records n bytes written locally; returns the window update to send.
func (w *recvWindow) drain(n int) (uint32, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.drained += charge(n)
	if w.drained < UpdateThreshold {
		return 0, false
	}
	add := w.drained
	w.drained = 0
	w.remaining += add
	return add, true
}

type inbound struct {
	data      []byte
	close     bool
	cancel    bool // the local side ends the channel (ctx done, local gone)
	violation bool
	refused   string
}

type channel struct {
	id     int32
	credit *sendCredit
	window *recvWindow
	in     chan inbound
	opened bool
}

// Tunnel is a multiplexed port-forward link.
type Tunnel struct {
	s        *peer.Session
	host     string
	port     int32
	mu       sync.Mutex
	channels map[int32]*channel
	nextID   int32
	dead     chan struct{}
	deadErr  error
	onError  func(string)
	reported map[string]time.Time
}

// NewTunnel starts the demultiplexer on a session logged in with
// PortForward{multiplex: true} whose peer announced port_forward_mux.
func NewTunnel(s *peer.Session, host string, port int32, onError func(string)) *Tunnel {
	t := &Tunnel{s: s, host: host, port: port, channels: map[int32]*channel{}, nextID: 1,
		dead: make(chan struct{}), onError: onError, reported: map[string]time.Time{}}
	go t.loop()
	// An idle channel (an ssh session nobody types into) carries nothing, and
	// a relay drops a silent link (hbbr after 30 s): probe while the tunnel lives.
	kctx, cancel := context.WithCancel(context.Background())
	go func() { <-t.dead; cancel() }()
	go s.KeepAlive(kctx, 20*time.Second)
	return t
}

// Done is closed when the tunnel ended.
func (t *Tunnel) Done() <-chan struct{} { return t.dead }

// Err is why the tunnel ended.
func (t *Tunnel) Err() error {
	<-t.dead
	return t.deadErr
}

// Close ends the tunnel and every channel.
func (t *Tunnel) Close() {
	t.s.Close("closed by user")
}

func (t *Tunnel) loop() {
	var err error
	for {
		var m *pb.Message
		m, err = t.s.Recv()
		if err != nil {
			break
		}
		if ch, ok := m.Union.(*pb.Message_PortForwardChannel); ok {
			t.onFrame(ch.PortForwardChannel)
		}
	}
	// Under the lock, so a Serve registering a channel either sees the tunnel
	// dead or has its channel in the map we close here.
	t.mu.Lock()
	t.deadErr = err
	chans := t.channels
	t.channels = map[int32]*channel{}
	close(t.dead)
	t.mu.Unlock()
	t.s.Close("")
	for _, c := range chans {
		c.deliver(inbound{close: true})
	}
}

func (c *channel) deliver(m inbound) {
	select {
	case c.in <- m:
	default:
		// the queue is sized for a full window of minimum-charge frames;
		// overflowing it means the peer ignored the window
	}
}

func (t *Tunnel) onFrame(f *pb.PortForwardChannel) {
	switch u := f.Union.(type) {
	case *pb.PortForwardChannel_Opened:
		o := u.Opened
		t.mu.Lock()
		c := t.channels[o.GetChannelId()]
		if c != nil && !o.GetSuccess() {
			delete(t.channels, o.GetChannelId())
		}
		t.mu.Unlock()
		if c == nil {
			return
		}
		if o.GetSuccess() {
			if !c.opened {
				c.opened = true
				c.credit.raiseInitial(o.GetWindow())
			}
			return
		}
		c.deliver(inbound{close: true, refused: o.GetMessage()})
		t.report(o.GetMessage())
	case *pb.PortForwardChannel_Data:
		d := u.Data
		t.mu.Lock()
		c := t.channels[d.GetChannelId()]
		if c == nil {
			t.mu.Unlock()
			return
		}
		if !c.window.accept(len(d.GetData())) {
			delete(t.channels, d.GetChannelId())
			t.mu.Unlock()
			c.deliver(inbound{violation: true})
			return
		}
		t.mu.Unlock()
		c.deliver(inbound{data: d.GetData()})
	case *pb.PortForwardChannel_Close:
		t.mu.Lock()
		c := t.channels[u.Close.GetChannelId()]
		delete(t.channels, u.Close.GetChannelId())
		t.mu.Unlock()
		if c != nil {
			// queued data still reaches local before the close
			c.deliver(inbound{close: true})
		}
	case *pb.PortForwardChannel_WindowUpdate:
		t.mu.Lock()
		c := t.channels[u.WindowUpdate.GetChannelId()]
		t.mu.Unlock()
		if c != nil {
			c.credit.add(u.WindowUpdate.GetAdd())
		}
	}
}

// report shows a refusal once per 10 s per reason (a page load can open a
// dozen connections refused for the same reason).
func (t *Tunnel) report(msg string) {
	if msg == "" || t.onError == nil {
		return
	}
	t.mu.Lock()
	now := time.Now()
	for k, at := range t.reported {
		if now.Sub(at) > 10*time.Second {
			delete(t.reported, k)
		}
	}
	_, seen := t.reported[msg]
	t.reported[msg] = now
	t.mu.Unlock()
	if !seen {
		t.onError(msg)
	}
}

func channelMsg(u isChannelUnion) *pb.Message {
	return &pb.Message{Union: &pb.Message_PortForwardChannel{PortForwardChannel: u.wrap()}}
}

type isChannelUnion interface{ wrap() *pb.PortForwardChannel }

type openU struct{ *pb.PortForwardOpen }
type dataU struct{ *pb.PortForwardData }
type closeU struct{ *pb.PortForwardClose }
type updateU struct{ *pb.PortForwardWindowUpdate }

func (u openU) wrap() *pb.PortForwardChannel {
	return &pb.PortForwardChannel{Union: &pb.PortForwardChannel_Open{Open: u.PortForwardOpen}}
}
func (u dataU) wrap() *pb.PortForwardChannel {
	return &pb.PortForwardChannel{Union: &pb.PortForwardChannel_Data{Data: u.PortForwardData}}
}
func (u closeU) wrap() *pb.PortForwardChannel {
	return &pb.PortForwardChannel{Union: &pb.PortForwardChannel_Close{Close: u.PortForwardClose}}
}
func (u updateU) wrap() *pb.PortForwardChannel {
	return &pb.PortForwardChannel{Union: &pb.PortForwardChannel_WindowUpdate{WindowUpdate: u.PortForwardWindowUpdate}}
}

// ErrTunnelGone means the tunnel ended before or while opening a channel.
var ErrTunnelGone = errors.New("port forward tunnel is gone")

// Serve runs one local connection as a channel until either side ends it
// or ctx is done. On ErrTunnelGone local is left open for a retry.
func (t *Tunnel) Serve(ctx context.Context, local io.ReadWriteCloser) error {
	t.mu.Lock()
	select {
	case <-t.dead:
		t.mu.Unlock()
		return ErrTunnelGone
	default:
	}
	if len(t.channels) >= MaxChannels {
		t.mu.Unlock()
		local.Close()
		return errors.New("too many port forward channels")
	}
	id := t.nextID
	for {
		if _, busy := t.channels[id]; !busy && id > 0 {
			break
		}
		id++
		if id <= 0 {
			id = 1
		}
	}
	t.nextID = id + 1
	if t.nextID <= 0 {
		t.nextID = 1
	}
	c := &channel{
		id:     id,
		credit: newSendCredit(InitialWindow),
		window: &recvWindow{remaining: ChannelWindow},
		// a full window of minimum-charge frames, plus close/cancel
		in: make(chan inbound, int(ChannelWindow/MinFrameCharge)+4),
	}
	t.channels[id] = c
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		if t.channels[id] == c {
			delete(t.channels, id)
		}
		t.mu.Unlock()
	}()

	if err := t.s.Send(channelMsg(openU{&pb.PortForwardOpen{ChannelId: id, Host: t.host, Port: t.port, Window: ChannelWindow}})); err != nil {
		return ErrTunnelGone
	}

	type end struct {
		fromReader                   bool
		eof                          bool
		local, peerClosed, violation bool
		refused                      string
	}
	ends := make(chan end, 2)
	// tunnel -> local deliveries, for the linger after a local EOF
	var delivered atomic.Int64

	// local -> tunnel, under the peer's credit
	go func() {
		buf := make([]byte, MaxFrame)
		for {
			allow, ok := c.credit.take(MaxFrame)
			if !ok {
				ends <- end{fromReader: true}
				return
			}
			n, err := local.Read(buf[:allow])
			spent := uint32(0)
			if n > 0 {
				spent = charge(n)
			}
			if spent < uint32(allow) {
				c.credit.add(uint32(allow) - spent)
			}
			if n > 0 {
				if t.s.Send(channelMsg(dataU{&pb.PortForwardData{ChannelId: id, Data: append([]byte(nil), buf[:n]...)}})) != nil {
					ends <- end{fromReader: true}
					return
				}
			}
			if err != nil {
				ends <- end{fromReader: true, local: true, eof: err == io.EOF}
				return
			}
		}
	}()

	// tunnel -> local: everything queued before a close is written first
	go func() {
		for m := range c.in {
			switch {
			case m.cancel:
				ends <- end{local: true}
				return
			case m.close:
				ends <- end{peerClosed: true, refused: m.refused}
				return
			case m.violation:
				ends <- end{violation: true}
				return
			}
			if _, err := local.Write(m.data); err != nil {
				ends <- end{local: true}
				return
			}
			delivered.Add(1)
			if add, ok := c.window.drain(len(m.data)); ok {
				if t.s.Send(channelMsg(updateU{&pb.PortForwardWindowUpdate{ChannelId: id, Add: add}})) != nil {
					ends <- end{}
					return
				}
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.deliver(inbound{cancel: true}) })
	defer stop()

	first := <-ends
	if first.eof {
		// The protocol has no half-close: the local side finished sending,
		// but the answer still comes (a request piped in and then EOF). Keep
		// delivering until the device closes, the writer fails, or, unless
		// the local end asks to wait indefinitely, nothing arrives for a
		// while (a client that closed completely would leak the channel).
		linger := DefaultLinger
		if l, ok := local.(interface{ LingerAfterEOF() time.Duration }); ok {
			linger = l.LingerAfterEOF()
		}
		if e, ok := waitIdle(ends, &delivered, linger); ok {
			first = e // the writer's end; the reader is already done
		}
	}
	// Stop the other half: closing local unblocks a socket read or write,
	// closing the credit a reader waiting for window.
	local.Close()
	c.credit.close()
	c.deliver(inbound{cancel: true})
	second := end{}
	if first.fromReader {
		// the writer still finishes what it holds, then sees the cancel
		second = <-ends
	}
	// After the peer closed (or the writer failed) the reader is not waited
	// for: a read from stdin cannot be interrupted, and it has nothing left
	// to deliver.
	peerClosed := first.peerClosed || second.peerClosed
	if !peerClosed && (first.local || first.violation || second.local || second.violation) {
		t.s.Send(channelMsg(closeU{&pb.PortForwardClose{ChannelId: id}}))
	}
	if first.refused != "" {
		return errors.New(first.refused)
	}
	return nil
}
