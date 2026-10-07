package mqtt

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"
)

type ClientOptions struct {
	ClientID  string
	Username  string
	Password  string
	TLS       *tls.Config
	KeepAlive time.Duration
	Timeout   time.Duration
}

type Client struct {
	conn     net.Conn
	r        *bufio.Reader
	wmu      sync.Mutex
	msgs     chan Message
	done     chan struct{}
	once     sync.Once
	err      error
	idMu     sync.Mutex
	nextID   uint16
	acks     map[uint16]chan []byte
	keep     time.Duration
	maxBytes int
}

func Dial(ctx context.Context, rawURL string, o ClientOptions) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("mqtt: invalid broker URL %q", rawURL)
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.KeepAlive <= 0 {
		o.KeepAlive = 60 * time.Second
	}
	if u.User != nil {
		if o.Username == "" {
			o.Username = u.User.Username()
		}
		if p, ok := u.User.Password(); ok && o.Password == "" {
			o.Password = p
		}
	}
	host := u.Hostname()
	port := u.Port()
	d := &net.Dialer{Timeout: o.Timeout, KeepAlive: 30 * time.Second}
	var conn net.Conn
	switch u.Scheme {
	case "mqtt", "tcp":
		if port == "" {
			port = "1883"
		}
		conn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	case "mqtts", "ssl", "tls":
		if port == "" {
			port = "8883"
		}
		cfg := o.TLS
		if cfg == nil {
			cfg = &tls.Config{}
		}
		cfg = cfg.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		td := &tls.Dialer{NetDialer: d, Config: cfg}
		conn, err = td.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	default:
		return nil, fmt.Errorf("mqtt: unsupported scheme %q (use mqtt:// or mqtts://)", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, r: bufio.NewReader(conn), msgs: make(chan Message, 1024), done: make(chan struct{}), acks: map[uint16]chan []byte{}, keep: o.KeepAlive, maxBytes: 1 << 20}
	flags := byte(0x02)
	payload := [][]byte{str(o.ClientID)}
	if o.Username != "" {
		flags |= 0x80
		payload = append(payload, str(o.Username))
		if o.Password != "" {
			flags |= 0x40
			payload = append(payload, str(o.Password))
		}
	}
	parts := append([][]byte{str("MQTT"), {4, flags}, u16(uint16(o.KeepAlive / time.Second))}, payload...)
	conn.SetDeadline(time.Now().Add(o.Timeout))
	if _, err := conn.Write(encode(typeConnect, 0, parts...)); err != nil {
		conn.Close()
		return nil, err
	}
	p, err := readPacket(c.r, 1024)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if p.kind != typeConnack || len(p.body) < 2 {
		conn.Close()
		return nil, ErrMalformed
	}
	if code := p.body[1]; code != 0 {
		conn.Close()
		reasons := map[byte]string{1: "unsupported protocol version", 2: "client id rejected", 3: "server unavailable", 4: "bad user name or password", 5: "not authorized"}
		return nil, fmt.Errorf("mqtt: connection refused: %s", reasons[code])
	}
	conn.SetDeadline(time.Time{})
	go c.readLoop()
	go c.pingLoop()
	return c, nil
}

func (c *Client) Messages() <-chan Message { return c.msgs }

func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) Err() error {
	<-c.done
	return c.err
}

func (c *Client) fail(err error) {
	c.once.Do(func() {
		c.err = err
		close(c.done)
		c.conn.Close()
	})
}

func (c *Client) Close() {
	c.write(encode(typeDisconnect, 0))
	c.fail(errors.New("mqtt: closed"))
}

func (c *Client) write(p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
	_, err := c.conn.Write(p)
	if err != nil {
		c.fail(err)
	}
	return err
}

func (c *Client) id() (uint16, chan []byte) {
	c.idMu.Lock()
	defer c.idMu.Unlock()
	c.nextID++
	if c.nextID == 0 {
		c.nextID = 1
	}
	ch := make(chan []byte, 1)
	c.acks[c.nextID] = ch
	return c.nextID, ch
}

func (c *Client) wait(id uint16, ch chan []byte) ([]byte, error) {
	defer func() {
		c.idMu.Lock()
		delete(c.acks, id)
		c.idMu.Unlock()
	}()
	select {
	case b := <-ch:
		return b, nil
	case <-c.done:
		return nil, c.err
	case <-time.After(20 * time.Second):
		return nil, errors.New("mqtt: no acknowledgement from the broker")
	}
}

func (c *Client) Subscribe(filters ...string) error {
	id, ch := c.id()
	parts := [][]byte{u16(id)}
	for _, f := range filters {
		parts = append(parts, str(f), []byte{0})
	}
	if err := c.write(encode(typeSubscribe, 2, parts...)); err != nil {
		return err
	}
	codes, err := c.wait(id, ch)
	if err != nil {
		return err
	}
	for i, code := range codes {
		if code == 0x80 {
			return fmt.Errorf("mqtt: subscription to %q refused", filters[min(i, len(filters)-1)])
		}
	}
	return nil
}

func (c *Client) Publish(topic string, payload []byte) error {
	if !validTopic(topic) {
		return fmt.Errorf("mqtt: invalid topic %q", topic)
	}
	return c.write(publishPacket(topic, payload, 0, 0, false))
}

func (c *Client) pingLoop() {
	t := time.NewTicker(c.keep / 2)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.write(encode(typePingreq, 0))
		}
	}
}

func (c *Client) readLoop() {
	for {
		c.conn.SetReadDeadline(time.Now().Add(c.keep * 2))
		p, err := readPacket(c.r, c.maxBytes)
		if err != nil {
			c.fail(err)
			close(c.msgs)
			return
		}
		switch p.kind {
		case typePublish:
			qos := (p.flags >> 1) & 3
			rd := &reader{b: p.body}
			topic := rd.string()
			var id uint16
			if qos > 0 {
				id = rd.uint16()
			}
			if rd.err != nil {
				c.fail(ErrMalformed)
				close(c.msgs)
				return
			}
			if qos == 1 {
				c.write(encode(typePuback, 0, u16(id)))
			} else if qos == 2 {
				c.write(encode(typePubrec, 0, u16(id)))
			}
			select {
			case c.msgs <- Message{Topic: topic, Payload: append([]byte(nil), rd.b...)}:
			default:
			}
		case typePubrel:
			rd := &reader{b: p.body}
			c.write(encode(typePubcomp, 0, u16(rd.uint16())))
		case typeSuback, typeUnsuback, typePuback:
			rd := &reader{b: p.body}
			id := rd.uint16()
			c.idMu.Lock()
			ch := c.acks[id]
			c.idMu.Unlock()
			if ch != nil {
				ch <- append([]byte(nil), rd.b...)
			}
		}
	}
}
