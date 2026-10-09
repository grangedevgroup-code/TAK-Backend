package grpcx

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

const (
	OK               = 0
	Canceled         = 1
	Unknown          = 2
	InvalidArgument  = 3
	NotFound         = 5
	PermissionDenied = 7
	Unimplemented    = 12
	Internal         = 13
	Unavailable      = 14
	Unauthenticated  = 16
)

type Status struct {
	Code    int
	Message string
}

func (s *Status) Error() string {
	return fmt.Sprintf("grpc status %d: %s", s.Code, s.Message)
}

func Errorf(code int, format string, args ...any) error {
	return &Status{Code: code, Message: fmt.Sprintf(format, args...)}
}

var ErrTooLarge = errors.New("grpc message exceeds the size limit")

func ReadMessage(r *bufio.Reader, max int, encoding string) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if int64(n) > int64(max) {
		return nil, ErrTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if hdr[0] == 0 {
		return buf, nil
	}
	if !strings.EqualFold(encoding, "gzip") {
		return nil, fmt.Errorf("compressed grpc message with unsupported encoding %q", encoding)
	}
	zr, err := gzip.NewReader(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > max {
		return nil, ErrTooLarge
	}
	return out, nil
}

func Frame(msg []byte) []byte {
	out := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg)))
	return append(out, msg...)
}

func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func percentDecode(s string) string {
	if out, err := url.PathUnescape(s); err == nil {
		return out
	}
	return s
}

type ServerStream struct {
	w        http.ResponseWriter
	r        *http.Request
	rc       *http.ResponseController
	br       *bufio.Reader
	max      int
	encoding string
	mu       sync.Mutex
	started  bool
}

func IsGRPC(r *http.Request) bool {
	return r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

func NewServerStream(w http.ResponseWriter, r *http.Request, max int) *ServerStream {
	return &ServerStream{w: w, r: r, rc: http.NewResponseController(w), br: bufio.NewReaderSize(r.Body, 64<<10), max: max, encoding: r.Header.Get("Grpc-Encoding")}
}

func (s *ServerStream) Context() context.Context { return s.r.Context() }

func (s *ServerStream) Request() *http.Request { return s.r }

func (s *ServerStream) start() {
	if s.started {
		return
	}
	s.started = true
	h := s.w.Header()
	h.Set("Content-Type", "application/grpc+proto")
	h.Set("Trailer", "Grpc-Status, Grpc-Message")
	s.w.WriteHeader(http.StatusOK)
	s.rc.Flush()
}

func (s *ServerStream) Recv() ([]byte, error) {
	return ReadMessage(s.br, s.max, s.encoding)
}

func (s *ServerStream) Send(msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.start()
	if _, err := s.w.Write(Frame(msg)); err != nil {
		return err
	}
	return s.rc.Flush()
}

func (s *ServerStream) Finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, msg := OK, ""
	if err != nil {
		var st *Status
		if errors.As(err, &st) {
			code, msg = st.Code, st.Message
		} else {
			code, msg = Unknown, err.Error()
		}
	}
	if !s.started {
		h := s.w.Header()
		h.Set("Content-Type", "application/grpc+proto")
		h.Set("Grpc-Status", strconv.Itoa(code))
		if msg != "" {
			h.Set("Grpc-Message", percentEncode(msg))
		}
		s.started = true
		s.w.WriteHeader(http.StatusOK)
		return
	}
	h := s.w.Header()
	h.Set("Grpc-Status", strconv.Itoa(code))
	if msg != "" {
		h.Set("Grpc-Message", percentEncode(msg))
	}
}

type ClientStream struct {
	pw       *io.PipeWriter
	done     chan struct{}
	resp     *http.Response
	err      error
	br       *bufio.Reader
	max      int
	cancel   context.CancelFunc
	sendMu   sync.Mutex
	closeMu  sync.Once
	encoding string
}

func Open(ctx context.Context, hc *http.Client, base, method string, headers http.Header, max int) (*ClientStream, error) {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/"+strings.TrimLeft(method, "/"), pr)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Grpc-Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", "grpc-go-golangtakserver/1.0")
	for k, v := range headers {
		req.Header[k] = v
	}
	cs := &ClientStream{pw: pw, done: make(chan struct{}), max: max, cancel: cancel}
	go func() {
		defer close(cs.done)
		resp, err := hc.Do(req)
		if err != nil {
			cs.err = err
			pr.CloseWithError(err)
			return
		}
		if resp.ProtoMajor != 2 {
			resp.Body.Close()
			cs.err = errors.New("the server did not answer over HTTP/2")
			pr.CloseWithError(cs.err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cs.err = fmt.Errorf("grpc call answered with HTTP %d", resp.StatusCode)
			pr.CloseWithError(cs.err)
			return
		}
		if st := statusFrom(resp.Header); st != nil && st.Code != OK {
			resp.Body.Close()
			cs.err = st
			pr.CloseWithError(st)
			return
		}
		cs.resp = resp
		cs.encoding = resp.Header.Get("Grpc-Encoding")
		cs.br = bufio.NewReaderSize(resp.Body, 64<<10)
	}()
	return cs, nil
}

func statusFrom(h http.Header) *Status {
	v := h.Get("Grpc-Status")
	if v == "" {
		return nil
	}
	code, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		code = Unknown
	}
	return &Status{Code: code, Message: percentDecode(h.Get("Grpc-Message"))}
}

func (c *ClientStream) Send(msg []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	_, err := c.pw.Write(Frame(msg))
	return err
}

func (c *ClientStream) CloseSend() error {
	var err error
	c.closeMu.Do(func() { err = c.pw.Close() })
	return err
}

func (c *ClientStream) Recv() ([]byte, error) {
	<-c.done
	if c.err != nil {
		return nil, c.err
	}
	msg, err := ReadMessage(c.br, c.max, c.encoding)
	if err == io.EOF {
		if st := statusFrom(c.resp.Trailer); st != nil && st.Code != OK {
			return nil, st
		}
		if st := statusFrom(c.resp.Header); st != nil && st.Code != OK {
			return nil, st
		}
		return nil, io.EOF
	}
	return msg, err
}

func (c *ClientStream) Close() {
	c.CloseSend()
	c.cancel()
	<-c.done
	if c.resp != nil {
		c.resp.Body.Close()
	}
}

func Unary(ctx context.Context, hc *http.Client, base, method string, headers http.Header, req []byte, max int) ([]byte, error) {
	cs, err := Open(ctx, hc, base, method, headers, max)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	if err := cs.Send(req); err != nil {
		if _, rerr := cs.Recv(); rerr != nil && rerr != io.EOF {
			return nil, rerr
		}
		return nil, err
	}
	cs.CloseSend()
	msg, err := cs.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, errors.New("grpc call ended without a response")
		}
		return nil, err
	}
	for {
		if _, err := cs.Recv(); err != nil {
			if err == io.EOF {
				return msg, nil
			}
			return msg, err
		}
	}
}
