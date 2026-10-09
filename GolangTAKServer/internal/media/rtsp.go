package media

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxRTSPHeader = 64 << 10
	maxRTSPBody   = 256 << 10
)

type Request struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
}

func (r *Request) Get(k string) string { return r.Header[strings.ToLower(k)] }

type Response struct {
	Status int
	Reason string
	Header map[string]string
	Body   []byte
}

func (r *Response) Get(k string) string { return r.Header[strings.ToLower(k)] }

func readHeaderLines(br *bufio.Reader) (first string, h map[string]string, err error) {
	h = map[string]string{}
	total := 0
	for {
		line, err := br.ReadString('\n')
		total += len(line)
		if total > maxRTSPHeader {
			return "", nil, errors.New("rtsp header too large")
		}
		if err != nil {
			return "", nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if first == "" {
			if line == "" {
				continue
			}
			first = line
			continue
		}
		if line == "" {
			return first, h, nil
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if old, dup := h[key]; dup && key == "www-authenticate" {
			h[key] = old + "\n" + strings.TrimSpace(v)
			continue
		}
		h[key] = strings.TrimSpace(v)
	}
}

func readBody(br *bufio.Reader, h map[string]string) ([]byte, error) {
	cl := h["content-length"]
	if cl == "" {
		return nil, nil
	}
	n, err := strconv.Atoi(cl)
	if err != nil || n < 0 || n > maxRTSPBody {
		return nil, errors.New("bad rtsp content length")
	}
	body := make([]byte, n)
	_, err = io.ReadFull(br, body)
	return body, err
}

func ReadRequest(br *bufio.Reader) (*Request, error) {
	first, h, err := readHeaderLines(br)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(first)
	if len(f) != 3 || !strings.HasPrefix(f[2], "RTSP/") {
		return nil, fmt.Errorf("bad rtsp request line %q", first)
	}
	body, err := readBody(br, h)
	if err != nil {
		return nil, err
	}
	return &Request{Method: strings.ToUpper(f[0]), URL: f[1], Header: h, Body: body}, nil
}

func ReadResponse(br *bufio.Reader) (*Response, error) {
	first, h, err := readHeaderLines(br)
	if err != nil {
		return nil, err
	}
	f := strings.SplitN(first, " ", 3)
	if len(f) < 2 || !strings.HasPrefix(f[0], "RTSP/") {
		return nil, fmt.Errorf("bad rtsp status line %q", first)
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		return nil, fmt.Errorf("bad rtsp status line %q", first)
	}
	resp := &Response{Status: code, Header: h}
	if len(f) == 3 {
		resp.Reason = f[2]
	}
	resp.Body, err = readBody(br, h)
	return resp, err
}

var reasons = map[int]string{200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 453: "Not Enough Bandwidth", 454: "Session Not Found", 455: "Method Not Valid in This State", 459: "Aggregate Operation Not Allowed", 461: "Unsupported Transport", 500: "Internal Server Error", 503: "Service Unavailable"}

func writeResponse(w io.Writer, cseq string, status int, h map[string]string, body []byte) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "RTSP/1.0 %d %s\r\nCSeq: %s\r\nServer: GolangTAKServer\r\nDate: %s\r\n", status, reasons[status], cseq, time.Now().UTC().Format(time.RFC1123))
	for k, v := range h {
		for _, line := range strings.Split(v, "\n") {
			fmt.Fprintf(&b, "%s: %s\r\n", k, line)
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	_, err := w.Write(b.Bytes())
	return err
}

func interleavedFrame(ch byte, data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = '$'
	out[1] = ch
	binary.BigEndian.PutUint16(out[2:], uint16(len(data)))
	copy(out[4:], data)
	return out
}

func newID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type transport struct {
	tcp        bool
	channels   [2]int
	clientPort [2]int
	record     bool
}

func parseTransport(v string) (transport, error) {
	var t transport
	t.channels = [2]int{-1, -1}
	for _, opt := range strings.Split(v, ",") {
		parts := strings.Split(strings.TrimSpace(opt), ";")
		proto := strings.ToUpper(parts[0])
		if !strings.HasPrefix(proto, "RTP/AVP") {
			continue
		}
		t = transport{channels: [2]int{-1, -1}, tcp: strings.HasSuffix(proto, "/TCP")}
		multicast := false
		for _, p := range parts[1:] {
			k, val, _ := strings.Cut(p, "=")
			switch strings.ToLower(k) {
			case "interleaved":
				a, b := parseRange(val)
				t.channels = [2]int{a, b}
			case "client_port":
				a, b := parseRange(val)
				t.clientPort = [2]int{a, b}
			case "mode":
				t.record = strings.Contains(strings.ToLower(val), "record")
			case "multicast":
				multicast = true
			}
		}
		if multicast {
			continue
		}
		return t, nil
	}
	return t, errors.New("no supported transport")
}

func parseRange(v string) (int, int) {
	a, b, ok := strings.Cut(v, "-")
	x, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return -1, -1
	}
	if !ok {
		return x, x + 1
	}
	y, err := strconv.Atoi(strings.TrimSpace(b))
	if err != nil {
		return x, x + 1
	}
	return x, y
}

func basicAuth(h string) (user, pass string, ok bool) {
	if !strings.HasPrefix(strings.ToLower(h), "basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

func urlPath(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	p := u.Path
	if p == "" {
		p = u.Opaque
	}
	return strings.Trim(p, "/"), nil
}

func splitControl(p string) (path, control string) {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		last := p[i+1:]
		if strings.HasPrefix(last, "trackID=") || strings.HasPrefix(last, "streamid=") || strings.HasPrefix(last, "track") || strings.HasPrefix(last, "stream=") {
			return p[:i], last
		}
	}
	return p, ""
}

func hostOnly(addr net.Addr) string {
	h, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return h
}
