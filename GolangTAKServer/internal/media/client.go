package media

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	u       *url.URL
	nc      net.Conn
	br      *bufio.Reader
	wmu     sync.Mutex
	cseq    int
	session string
	auth    func(method, uri string) string
	base    string
}

func Dial(ctx context.Context, raw string, tlsCfg *tls.Config) (*Client, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "rtsps" {
			host = net.JoinHostPort(u.Hostname(), "322")
		} else {
			host = net.JoinHostPort(u.Hostname(), "554")
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var nc net.Conn
	if u.Scheme == "rtsps" {
		cfg := tlsCfg
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		cfg = cfg.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		nc, err = (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", host)
	} else if u.Scheme == "rtsp" {
		nc, err = d.DialContext(ctx, "tcp", host)
	} else {
		return nil, fmt.Errorf("unsupported scheme %q, use rtsp or rtsps", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	c := &Client{u: u, nc: nc, br: bufio.NewReaderSize(nc, 64<<10)}
	return c, nil
}

func (c *Client) Close() error { return c.nc.Close() }

func (c *Client) cleanURL() string {
	u := *c.u
	u.User = nil // nosemgrep -- u is a copy
	return u.String()
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func digestParams(v string) map[string]string {
	out := map[string]string{}
	for _, part := range splitQuoted(v) {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			out[strings.ToLower(k)] = strings.Trim(val, `"`)
		}
	}
	return out
}

func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	q := false
	for _, r := range s {
		switch {
		case r == '"':
			q = !q
			cur.WriteRune(r)
		case r == ',' && !q:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, cur.String())
}

func (c *Client) setAuth(challenges string) error {
	if c.u.User == nil {
		return ErrUnauthorized
	}
	user := c.u.User.Username()
	pass, _ := c.u.User.Password()
	var digest, basic string
	for _, ch := range strings.Split(challenges, "\n") {
		ch = strings.TrimSpace(ch)
		low := strings.ToLower(ch)
		if strings.HasPrefix(low, "digest ") {
			digest = ch[7:]
		} else if strings.HasPrefix(low, "basic") {
			basic = ch
		}
	}
	if digest != "" {
		p := digestParams(digest)
		realm, nonce, opaque := p["realm"], p["nonce"], p["opaque"]
		qop := ""
		for _, q := range strings.Split(p["qop"], ",") {
			if strings.TrimSpace(q) == "auth" {
				qop = "auth"
			}
		}
		nc := 0
		c.auth = func(method, uri string) string {
			ha1 := md5hex(user + ":" + realm + ":" + pass)
			ha2 := md5hex(method + ":" + uri)
			h := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s"`, user, realm, nonce, uri)
			if qop != "" {
				nc++
				ncs := fmt.Sprintf("%08x", nc)
				cnonce := newID(8)
				h += fmt.Sprintf(`, response="%s", qop=auth, nc=%s, cnonce="%s"`, md5hex(ha1+":"+nonce+":"+ncs+":"+cnonce+":auth:"+ha2), ncs, cnonce)
			} else {
				h += fmt.Sprintf(`, response="%s"`, md5hex(ha1+":"+nonce+":"+ha2))
			}
			if opaque != "" {
				h += fmt.Sprintf(`, opaque="%s"`, opaque)
			}
			return h
		}
		return nil
	}
	if basic != "" || challenges == "" {
		tok := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		c.auth = func(string, string) string { return tok }
		return nil
	}
	return ErrUnauthorized
}

func (c *Client) Do(method, uri string, h map[string]string, body []byte) (*Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		c.cseq++
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s RTSP/1.0\r\nCSeq: %d\r\nUser-Agent: GolangTAKServer\r\n", method, uri, c.cseq)
		if c.session != "" {
			fmt.Fprintf(&b, "Session: %s\r\n", c.session)
		}
		if c.auth != nil {
			fmt.Fprintf(&b, "Authorization: %s\r\n", c.auth(method, uri))
		}
		for k, v := range h {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
		if len(body) > 0 {
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		}
		b.WriteString("\r\n")
		c.wmu.Lock()
		c.nc.SetDeadline(time.Now().Add(15 * time.Second))
		_, err := io.WriteString(c.nc, b.String())
		if err == nil && len(body) > 0 {
			_, err = c.nc.Write(body)
		}
		c.wmu.Unlock()
		if err != nil {
			return nil, err
		}
		resp, err := c.readResponse()
		if err != nil {
			return nil, err
		}
		if resp.Status == 401 && attempt == 0 && c.auth == nil {
			if err := c.setAuth(resp.Get("www-authenticate")); err != nil {
				return nil, err
			}
			continue
		}
		if id := resp.Get("session"); id != "" {
			c.session, _, _ = strings.Cut(id, ";")
		}
		if resp.Status == 401 {
			return resp, ErrUnauthorized
		}
		if resp.Status != 200 {
			return resp, fmt.Errorf("%s answered %d %s", method, resp.Status, resp.Reason)
		}
		return resp, nil
	}
	return nil, ErrUnauthorized
}

func (c *Client) readResponse() (*Response, error) {
	for {
		b, err := c.br.Peek(1)
		if err != nil {
			return nil, err
		}
		if b[0] == '$' {
			var hdr [4]byte
			if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
				return nil, err
			}
			if _, err := c.br.Discard(int(hdr[2])<<8 | int(hdr[3])); err != nil {
				return nil, err
			}
			continue
		}
		return ReadResponse(c.br)
	}
}

func (c *Client) trackURL(t *Track) string {
	if t.Control == "" || t.Control == "*" {
		return c.base
	}
	if strings.Contains(t.Control, "://") {
		return t.Control
	}
	return strings.TrimRight(c.base, "/") + "/" + t.Control
}

func (c *Client) Describe() (*Description, error) {
	clean := c.cleanURL()
	if _, err := c.Do("OPTIONS", clean, nil, nil); err != nil && !errors.Is(err, ErrUnauthorized) {
		if _, ok := err.(net.Error); ok {
			return nil, err
		}
	}
	resp, err := c.Do("DESCRIBE", clean, map[string]string{"Accept": "application/sdp"}, nil)
	if err != nil {
		return nil, err
	}
	c.base = firstNonEmpty(resp.Get("content-base"), resp.Get("content-location"), clean)
	return ParseSDP(resp.Body)
}

func (c *Client) SetupPlay(desc *Description) error {
	for i, t := range desc.Tracks {
		if _, err := c.Do("SETUP", c.trackURL(t), map[string]string{"Transport": fmt.Sprintf("RTP/AVP/TCP;unicast;interleaved=%d-%d", i*2, i*2+1)}, nil); err != nil {
			return err
		}
	}
	_, err := c.Do("PLAY", c.base, map[string]string{"Range": "npt=0.000-"}, nil)
	return err
}

func (c *Client) ReadPackets(timeout time.Duration, fn func(Packet)) error {
	for {
		c.nc.SetReadDeadline(time.Now().Add(timeout))
		b, err := c.br.Peek(1)
		if err != nil {
			return err
		}
		if b[0] != '$' {
			if _, err := ReadResponse(c.br); err != nil {
				return err
			}
			continue
		}
		var hdr [4]byte
		if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
			return err
		}
		data := make([]byte, int(hdr[2])<<8|int(hdr[3]))
		if _, err := io.ReadFull(c.br, data); err != nil {
			return err
		}
		fn(Packet{Track: int(hdr[1]) / 2, RTCP: hdr[1]%2 == 1, Data: data})
	}
}

func (c *Client) KeepAlive(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.cseq++
			var b strings.Builder
			fmt.Fprintf(&b, "GET_PARAMETER %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n", c.base, c.cseq, c.session)
			if c.auth != nil {
				fmt.Fprintf(&b, "Authorization: %s\r\n", c.auth("GET_PARAMETER", c.base))
			}
			b.WriteString("\r\n")
			c.wmu.Lock()
			c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := io.WriteString(c.nc, b.String())
			c.wmu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (c *Client) Announce(desc *Description) error {
	clean := c.cleanURL()
	c.base = clean
	if _, err := c.Do("ANNOUNCE", clean, map[string]string{"Content-Type": "application/sdp"}, desc.Marshal("")); err != nil {
		return err
	}
	for i := range desc.Tracks {
		if _, err := c.Do("SETUP", clean+"/trackID="+strconv.Itoa(i), map[string]string{"Transport": fmt.Sprintf("RTP/AVP/TCP;unicast;interleaved=%d-%d;mode=record", i*2, i*2+1)}, nil); err != nil {
			return err
		}
	}
	_, err := c.Do("RECORD", clean, map[string]string{"Range": "npt=0.000-"}, nil)
	return err
}

func (c *Client) WritePacket(p Packet) error {
	ch := byte(p.Track * 2)
	if p.RTCP {
		ch++
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.nc.Write(interleavedFrame(ch, p.Data))
	return err
}

func Pull(ctx context.Context, raw string, tlsCfg *tls.Config, reg *Registry, path, publisher string) error {
	c, err := Dial(ctx, raw, tlsCfg)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	desc, err := c.Describe()
	if err != nil {
		return err
	}
	if err := c.SetupPlay(desc); err != nil {
		return err
	}
	st, err := reg.Publish(path, desc, publisher, "pull "+c.cleanURL())
	if err != nil {
		return err
	}
	defer reg.Unpublish(st)
	kctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.KeepAlive(kctx, 25*time.Second)
	return c.ReadPackets(30*time.Second, st.Write)
}
