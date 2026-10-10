package websocket

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
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
	"unicode/utf8"
)

const (
	OpContinuation = 0
	OpText         = 1
	OpBinary       = 2
	OpClose        = 8
	OpPing         = 9
	OpPong         = 10
)

const (
	CloseNormal          = 1000
	CloseGoingAway       = 1001
	CloseProtocolError   = 1002
	CloseUnsupportedData = 1003
	CloseInvalidPayload  = 1007
	ClosePolicyViolation = 1008
	CloseTooBig          = 1009
	CloseInternalError   = 1011
	CloseTryAgainLater   = 1013
)

const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var (
	ErrBadHandshake = errors.New("websocket: bad handshake")
	ErrTooBig       = errors.New("websocket: message too large")
	ErrProtocol     = errors.New("websocket: protocol error")
	ErrClosed       = errors.New("websocket: connection closed")
)

type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("websocket: closed with code %d %s", e.Code, e.Reason)
}

type Conn struct {
	conn        net.Conn
	br          *bufio.Reader
	client      bool
	wmu         sync.Mutex
	MaxMessage  int64
	subprotocol string
	closeOnce   sync.Once
	sentClose   bool
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

func headerContains(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, p := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

func IsUpgrade(r *http.Request) bool {
	return headerContains(r.Header, "Connection", "upgrade") && headerContains(r.Header, "Upgrade", "websocket")
}

func Accept(w http.ResponseWriter, r *http.Request, subprotocols []string) (*Conn, error) {
	if r.Method != http.MethodGet || !IsUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return nil, ErrBadHandshake
	}
	if r.Header.Get("Sec-Websocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "unsupported websocket version", http.StatusUpgradeRequired)
		return nil, ErrBadHandshake
	}
	key := strings.TrimSpace(r.Header.Get("Sec-Websocket-Key"))
	if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 16 {
		http.Error(w, "bad websocket key", http.StatusBadRequest)
		return nil, ErrBadHandshake
	}
	chosen := ""
	if len(subprotocols) > 0 {
		for _, offered := range strings.Split(r.Header.Get("Sec-Websocket-Protocol"), ",") {
			offered = strings.TrimSpace(offered)
			for _, s := range subprotocols {
				if chosen == "" && offered == s {
					chosen = s
				}
			}
		}
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported on this connection", http.StatusInternalServerError)
		return nil, ErrBadHandshake
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	var resp strings.Builder
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	resp.WriteString(acceptKey(key))
	resp.WriteString("\r\n")
	if chosen != "" {
		resp.WriteString("Sec-WebSocket-Protocol: " + chosen + "\r\n")
	}
	resp.WriteString("\r\n")
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(resp.String())); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})
	conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, br: brw.Reader, MaxMessage: 16 << 20, subprotocol: chosen}, nil
}

type DialOptions struct {
	TLS          *tls.Config
	Header       http.Header
	Subprotocols []string
	Timeout      time.Duration
}

func Dial(ctx context.Context, rawURL string, opts *DialOptions) (*Conn, *http.Response, error) {
	if opts == nil {
		opts = &DialOptions{}
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	secure := false
	switch u.Scheme {
	case "ws", "http":
	case "wss", "https":
		secure = true
	default:
		return nil, nil, fmt.Errorf("websocket: unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		if secure {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	var conn net.Conn
	if secure {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if opts.TLS != nil {
			cfg = opts.TLS.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		cfg.NextProtos = []string{"http/1.1"}
		td := &tls.Dialer{NetDialer: d, Config: cfg}
		conn, err = td.DialContext(ctx, "tcp", host)
	} else {
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, err
	}
	keyRaw := make([]byte, 16)
	rand.Read(keyRaw)
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	var req strings.Builder
	req.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n")
	if len(opts.Subprotocols) > 0 {
		req.WriteString("Sec-WebSocket-Protocol: " + strings.Join(opts.Subprotocols, ", ") + "\r\n")
	}
	if u.User != nil && opts.Header.Get("Authorization") == "" {
		pw, _ := u.User.Password()
		req.WriteString("Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)) + "\r\n")
	}
	for k, vs := range opts.Header {
		for _, v := range vs {
			req.WriteString(k + ": " + strings.NewReplacer("\r", "", "\n", "").Replace(v) + "\r\n")
		}
	}
	req.WriteString("\r\n")
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	if _, err := conn.Write([]byte(req.String())); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReaderSize(conn, 32<<10)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet, URL: u})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !headerContains(resp.Header, "Upgrade", "websocket") || resp.Header.Get("Sec-Websocket-Accept") != acceptKey(key) {
		conn.Close()
		return nil, resp, fmt.Errorf("%w: status %s", ErrBadHandshake, resp.Status)
	}
	conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, br: br, client: true, MaxMessage: 16 << 20, subprotocol: resp.Header.Get("Sec-Websocket-Protocol")}, resp, nil
}

func (c *Conn) Subprotocol() string { return c.subprotocol }

func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *Conn) NetConn() net.Conn { return c.conn }

func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *Conn) writeFrame(op int, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.sentClose {
		return ErrClosed
	}
	if op == OpClose {
		c.sentClose = true
	}
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|byte(op))
	mask := byte(0)
	if c.client {
		mask = 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, mask|byte(n))
	case n < 1<<16:
		hdr = append(hdr, mask|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, mask|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	if c.client {
		var key [4]byte
		rand.Read(key[:])
		hdr = append(hdr, key[:]...)
		masked := make([]byte, n)
		for i := range payload {
			masked[i] = payload[i] ^ key[i&3]
		}
		payload = masked
	}
	if len(payload) <= 4096 {
		buf := append(hdr, payload...)
		_, err := c.conn.Write(buf)
		return err
	}
	bufs := net.Buffers{hdr, payload}
	_, err := bufs.WriteTo(c.conn)
	return err
}

func (c *Conn) WriteMessage(op int, data []byte) error { return c.writeFrame(op, data) }

func (c *Conn) WriteText(s string) error { return c.writeFrame(OpText, []byte(s)) }

func (c *Conn) WriteBinary(b []byte) error { return c.writeFrame(OpBinary, b) }

func (c *Conn) Ping(data []byte) error { return c.writeFrame(OpPing, data) }

func (c *Conn) Close(code int, reason string) error {
	var err error
	c.closeOnce.Do(func() {
		if len(reason) > 120 {
			reason = reason[:120]
		}
		payload := binary.BigEndian.AppendUint16(nil, uint16(code))
		payload = append(payload, reason...)
		c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		c.writeFrame(OpClose, payload)
		err = c.conn.Close()
	})
	return err
}

func (c *Conn) CloseNow() error {
	var err error
	c.closeOnce.Do(func() { err = c.conn.Close() })
	return err
}

func (c *Conn) fail(code int, reason string) {
	payload := binary.BigEndian.AppendUint16(nil, uint16(code))
	payload = append(payload, reason...)
	c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	c.writeFrame(OpClose, payload)
	if tc, ok := c.conn.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	}
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.CopyN(io.Discard, c.br, 64<<20)
	c.CloseNow()
}

type frame struct {
	fin     bool
	op      int
	payload []byte
}

func (c *Conn) readFrame(limit int64) (frame, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: h[0]&0x80 != 0, op: int(h[0] & 0x0f)}
	if h[0]&0x70 != 0 {
		return f, ErrProtocol
	}
	masked := h[1]&0x80 != 0
	if masked == c.client {
		return f, ErrProtocol
	}
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return f, err
		}
		n = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return f, err
		}
		v := binary.BigEndian.Uint64(b[:])
		if v > 1<<62 {
			return f, ErrProtocol
		}
		n = int64(v)
	}
	if f.op >= 8 {
		if !f.fin || n > 125 {
			return f, ErrProtocol
		}
	} else if limit > 0 && n > limit {
		return f, ErrTooBig
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, key[:]); err != nil {
			return f, err
		}
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(c.br, f.payload); err != nil {
		return f, err
	}
	if masked {
		for i := range f.payload {
			f.payload[i] ^= key[i&3]
		}
	}
	return f, nil
}

func (c *Conn) ReadMessage() (int, []byte, error) {
	var op int
	var msg []byte
	for {
		remaining := c.MaxMessage - int64(len(msg))
		f, err := c.readFrame(remaining)
		if err != nil {
			if err == ErrTooBig {
				c.fail(CloseTooBig, "message too large")
			} else if err == ErrProtocol {
				c.fail(CloseProtocolError, "protocol error")
			}
			return 0, nil, err
		}
		switch f.op {
		case OpPing:
			c.writeFrame(OpPong, f.payload)
			continue
		case OpPong:
			continue
		case OpClose:
			code := CloseNormal
			reason := ""
			if len(f.payload) >= 2 {
				code = int(binary.BigEndian.Uint16(f.payload))
				reason = string(f.payload[2:])
			}
			c.wmu.Lock()
			already := c.sentClose
			c.wmu.Unlock()
			if !already {
				c.writeFrame(OpClose, f.payload[:min(2, len(f.payload))])
			}
			c.CloseNow()
			return 0, nil, &CloseError{Code: code, Reason: reason}
		case OpText, OpBinary:
			if msg != nil {
				c.fail(CloseProtocolError, "unexpected data frame")
				return 0, nil, ErrProtocol
			}
			op = f.op
			msg = f.payload
			if msg == nil {
				msg = []byte{}
			}
		case OpContinuation:
			if msg == nil {
				c.fail(CloseProtocolError, "unexpected continuation")
				return 0, nil, ErrProtocol
			}
			msg = append(msg, f.payload...)
		default:
			c.fail(CloseProtocolError, "unknown opcode")
			return 0, nil, ErrProtocol
		}
		if f.fin {
			if op == OpText && !utf8.Valid(msg) {
				c.fail(CloseInvalidPayload, "invalid utf-8")
				return 0, nil, ErrProtocol
			}
			return op, msg, nil
		}
	}
}
