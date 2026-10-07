package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
)

const (
	KindTCP        = "tcp"
	KindTLS        = "tls"
	KindWebSocket  = "websocket"
	KindUDP        = "udp"
	KindMesh       = "mesh"
	KindPeer       = "peer"
	KindFederation = "federation"
	KindAPI        = "api"
	KindServer     = "server"
)

type Message struct {
	Event       *cot.Event
	Source      *Client
	Groups      GroupMask
	Everyone    bool
	Received    time.Time
	NoReplay    bool
	NoHistory   bool
	ForceXML    bool
	SwitchProto bool
	Disconnect  bool
	Announce    string
	Hops        int64
	xmlOnce     sync.Once
	xml         []byte
	pbOnce      sync.Once
	pb          []byte
	frameOnce   sync.Once
	frame       []byte
}

func NewMessage(e *cot.Event, src *Client, groups GroupMask) *Message {
	return &Message{Event: e, Source: src, Groups: groups, Received: time.Now()}
}

func (m *Message) XML() []byte {
	m.xmlOnce.Do(func() { m.xml = m.Event.XML() })
	return m.xml
}

func (m *Message) Proto() []byte {
	m.pbOnce.Do(func() { m.pb = takproto.Marshal(m.Event) })
	return m.pb
}

func (m *Message) StreamFrame() []byte {
	m.frameOnce.Do(func() {
		pb := m.Proto()
		m.frame = takproto.AppendStreamFrame(make([]byte, 0, len(pb)+6), pb)
	})
	return m.frame
}

type ClientInfo struct {
	UID      string    `json:"uid"`
	Callsign string    `json:"callsign"`
	Team     string    `json:"team"`
	Role     string    `json:"role"`
	Device   string    `json:"device"`
	Platform string    `json:"platform"`
	OS       string    `json:"os"`
	Version  string    `json:"version"`
	Phone    string    `json:"phone"`
	Type     string    `json:"type"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Hae      float64   `json:"hae"`
	Speed    float64   `json:"speed"`
	Course   float64   `json:"course"`
	Battery  string    `json:"battery"`
	LastSA   time.Time `json:"lastSA"`
}

type Client struct {
	ID        uint64
	Kind      string
	Remote    string
	Name      string
	Connected time.Time
	Relay     bool
	ident     atomic.Pointer[Identity]
	mu        sync.Mutex
	info      ClientInfo
	lastSA    *Message
	remote    map[string]string
	out       chan *Message
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func()
	proto     atomic.Bool
	lastRx    atomic.Int64
	rx        atomic.Uint64
	tx        atomic.Uint64
	drops     atomic.Uint64
	authed    atomic.Bool
	hub       *Hub
	filter    func(*Message) bool
	geo       atomic.Pointer[geoFilter]
	metrics   map[string]string
}

type bbox struct{ minLat, minLon, maxLat, maxLon float64 }

func (b bbox) contains(lat, lon float64) bool {
	return lat >= b.minLat && lat <= b.maxLat && lon >= b.minLon && lon <= b.maxLon
}

type geoFilter struct {
	boxes  []bbox
	allTAK bool
}

func (g *geoFilter) passes(m *Message) bool {
	if g == nil || len(g.boxes) == 0 {
		return true
	}
	e := m.Event
	if e.IsControl() || e.IsChat() || e.Is("b-a-") || len(e.Dests()) > 0 {
		return true
	}
	if g.allTAK && e.IsSA() {
		return true
	}
	for _, b := range g.boxes {
		if b.contains(e.Point.Lat, e.Point.Lon) {
			return true
		}
	}
	return false
}

func (c *Client) Metrics() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.metrics))
	for k, v := range c.metrics {
		out[k] = v
	}
	return out
}

func (c *Client) Identity() *Identity { return c.ident.Load() }

func (c *Client) SetIdentity(id *Identity) { c.ident.Store(id) }

func (c *Client) User() string {
	if id := c.ident.Load(); id != nil {
		return id.Name
	}
	return ""
}

func (c *Client) InMask() GroupMask {
	if id := c.ident.Load(); id != nil {
		return id.In
	}
	return nil
}

func (c *Client) OutMask() GroupMask {
	if id := c.ident.Load(); id != nil {
		return id.Out
	}
	return nil
}

func (c *Client) Info() ClientInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info
}

func (c *Client) UID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info.UID
}

func (c *Client) Callsign() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info.Callsign
}

func (c *Client) UseProto() bool { return c.proto.Load() }

func (c *Client) SetProto(v bool) { c.proto.Store(v) }

func (c *Client) Closed() <-chan struct{} { return c.closed }

func (c *Client) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.onClose != nil {
			c.onClose()
		}
	})
}

func (c *Client) Send(m *Message) bool {
	if c.filter != nil && !c.filter(m) {
		return false
	}
	if g := c.geo.Load(); g != nil && !g.passes(m) {
		return false
	}
	select {
	case <-c.closed:
		return false
	default:
	}
	select {
	case c.out <- m:
		return true
	default:
		c.drops.Add(1)
		return false
	}
}

func (c *Client) Out() <-chan *Message { return c.out }

func (c *Client) touch() {
	c.lastRx.Store(time.Now().UnixNano())
	c.rx.Add(1)
}

func (c *Client) LastSeen() time.Time {
	v := c.lastRx.Load()
	if v == 0 {
		return c.Connected
	}
	return time.Unix(0, v)
}

func (c *Client) Sent() { c.tx.Add(1) }

type ClientView struct {
	ID        uint64     `json:"id"`
	Kind      string     `json:"kind"`
	Name      string     `json:"name,omitempty"`
	Remote    string     `json:"remote"`
	User      string     `json:"user"`
	Groups    []string   `json:"groups"`
	Protocol  string     `json:"protocol"`
	Connected time.Time  `json:"connected"`
	LastSeen  time.Time  `json:"lastSeen"`
	Rx        uint64     `json:"rx"`
	Tx        uint64     `json:"tx"`
	Dropped   uint64     `json:"dropped"`
	Contacts  int        `json:"contacts,omitempty"`
	Internal  bool       `json:"internal,omitempty"`
	Info      ClientInfo `json:"info"`
}

func (c *Client) Internal() bool {
	return c.Relay && (c.Kind == KindUDP || c.Kind == KindMesh || c.Kind == KindAPI || c.Kind == KindServer)
}
