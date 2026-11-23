// Package wire carries RustDesk messages over TCP (hbb_common's BytesCodec
// framing) or WebSocket (one message per binary frame).
package wire

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// MaxFrame is the largest frame the codec can express (30 bits).
const MaxFrame = 0x3FFF_FFFF

// DefaultMaxPacket caps what we accept in one frame from the network.
const DefaultMaxPacket = 64 << 20

// Conn is one message-oriented link to hbbs, hbbr or (through hbbr) a peer.
// Send and Recv may be called from different goroutines; neither is safe for
// concurrent use with itself.
type Conn interface {
	Send(msg []byte) error
	// Recv returns the next message. In raw mode it returns whatever bytes
	// arrived, without framing.
	Recv() ([]byte, error)
	// SetRaw switches to unframed bytes both ways (legacy port forwarding
	// after login).
	SetRaw()
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	RemoteAddr() string
	Close() error
}

// ErrTooBig reports a frame over the limit.
var ErrTooBig = errors.New("frame too big")

// AppendHeader appends the BytesCodec length header for n bytes.
func AppendHeader(dst []byte, n int) ([]byte, error) {
	switch {
	case n <= 0x3F:
		return append(dst, byte(n<<2)), nil
	case n <= 0x3FFF:
		return binary.LittleEndian.AppendUint16(dst, uint16(n<<2)|1), nil
	case n <= 0x3FFFFF:
		h := uint32(n<<2) | 2
		dst = binary.LittleEndian.AppendUint16(dst, uint16(h))
		return append(dst, byte(h>>16)), nil
	case n <= MaxFrame:
		return binary.LittleEndian.AppendUint32(dst, uint32(n<<2)|3), nil
	default:
		return dst, ErrTooBig
	}
}

// ReadFrame reads one framed message.
func ReadFrame(r *bufio.Reader, max int) ([]byte, error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	headLen := int(first&3) + 1
	n := int(first)
	for i := 1; i < headLen; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return nil, unexpected(err)
		}
		n |= int(b) << (8 * i)
	}
	n >>= 2
	if n > max {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooBig, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, unexpected(err)
	}
	return buf, nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// TCP is a framed TCP connection.
type TCP struct {
	c       net.Conn
	r       *bufio.Reader
	raw     bool
	max     int
	scratch []byte
	wmu     sync.Mutex
}

// DialTCP connects to host:port.
func DialTCP(ctx context.Context, addr string) (*TCP, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return NewTCP(c), nil
}

// NewTCP wraps an established connection.
func NewTCP(c net.Conn) *TCP {
	return &TCP{c: c, r: bufio.NewReaderSize(c, 64<<10), max: DefaultMaxPacket, scratch: make([]byte, 64<<10)}
}

func (t *TCP) Send(msg []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.raw {
		_, err := t.c.Write(msg)
		return err
	}
	buf, err := AppendHeader(make([]byte, 0, len(msg)+4), len(msg))
	if err != nil {
		return err
	}
	_, err = t.c.Write(append(buf, msg...))
	return err
}

func (t *TCP) Recv() ([]byte, error) {
	if t.raw {
		n, err := t.r.Read(t.scratch)
		if n > 0 {
			return append([]byte(nil), t.scratch[:n]...), nil
		}
		return nil, err
	}
	return ReadFrame(t.r, t.max)
}

func (t *TCP) SetRaw() {
	t.wmu.Lock()
	t.raw = true
	t.wmu.Unlock()
}

func (t *TCP) SetReadDeadline(d time.Time) error  { return t.c.SetReadDeadline(d) }
func (t *TCP) SetWriteDeadline(d time.Time) error { return t.c.SetWriteDeadline(d) }
func (t *TCP) RemoteAddr() string                 { return t.c.RemoteAddr().String() }
func (t *TCP) Close() error                       { return t.c.Close() }

// WS is a WebSocket connection carrying one message per binary frame.
type WS struct {
	c   *websocket.Conn
	wmu sync.Mutex
}

// DialWS opens a ws:// or wss:// URL.
func DialWS(ctx context.Context, rawURL string, insecure bool) (*WS, error) {
	d := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  64 << 10,
	}
	if insecure {
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit --insecure
	}
	c, resp, err := d.DialContext(ctx, rawURL, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("%s: %s", Redact(rawURL), resp.Status)
		}
		return nil, fmt.Errorf("%s: %w", Redact(rawURL), err)
	}
	c.SetReadLimit(DefaultMaxPacket)
	return &WS{c: c}, nil
}

func (w *WS) Send(msg []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.c.WriteMessage(websocket.BinaryMessage, msg)
}

func (w *WS) Recv() ([]byte, error) {
	for {
		typ, data, err := w.c.ReadMessage()
		if err != nil {
			return nil, err
		}
		if typ == websocket.BinaryMessage {
			return data, nil
		}
	}
}

// SetRaw is a no-op: WebSocket frames delimit messages either way.
func (w *WS) SetRaw()                            {}
func (w *WS) SetReadDeadline(d time.Time) error  { return w.c.SetReadDeadline(d) }
func (w *WS) SetWriteDeadline(d time.Time) error { return w.c.SetWriteDeadline(d) }
func (w *WS) RemoteAddr() string                 { return w.c.RemoteAddr().String() }
func (w *WS) Close() error {
	// Not under wmu: a Send stuck on a full socket holds it, and Close is
	// what unblocks it. gorilla allows WriteControl beside other writers.
	w.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	return w.c.Close()
}

// IsWS reports whether addr is a WebSocket URL.
func IsWS(addr string) bool {
	return strings.HasPrefix(addr, "ws://") || strings.HasPrefix(addr, "wss://")
}

// Dial opens addr: a ws(s):// URL, or host[:port] over TCP with defPort.
func Dial(ctx context.Context, addr string, defPort int, insecure bool) (Conn, error) {
	if IsWS(addr) {
		return DialWS(ctx, addr, insecure)
	}
	return DialTCP(ctx, WithPort(addr, defPort))
}

// WithPort adds defPort to a host without one (IPv6 literals included).
func WithPort(addr string, defPort int) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	return net.JoinHostPort(host, fmt.Sprint(defPort))
}

// Redact drops the query string of a URL for error messages.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexByte(raw, '?'); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}
