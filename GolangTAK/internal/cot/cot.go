package cot

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/xmltree"
)

const TimeLayout = "2006-01-02T15:04:05.000Z"

const Unknown = 9999999.0

var (
	ErrNotEvent = errors.New("cot: root element is not <event>")
	ErrNoUID    = errors.New("cot: event has no uid")
	ErrNoType   = errors.New("cot: event has no type")
)

type Point struct {
	Lat float64
	Lon float64
	Hae float64
	Ce  float64
	Le  float64
}

type Event struct {
	Version    string
	UID        string
	Type       string
	How        string
	Time       time.Time
	Start      time.Time
	Stale      time.Time
	Access     string
	QoS        string
	Opex       string
	Caveat     string
	Releasable string
	Extra      []xmltree.Attr
	Point      Point
	Detail     *xmltree.Node
}

type Dest struct {
	UID      string
	Callsign string
	Mission  string
	Group    string
}

type Link struct {
	UID      string
	Type     string
	Relation string
	Callsign string
}

func FormatTime(t time.Time) string {
	return t.UTC().Format(TimeLayout)
}

var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04Z07:00",
}

func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("cot: empty time")
	}
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		if ms > 1e12 {
			return time.UnixMilli(ms).UTC(), nil
		}
		return time.Unix(ms, 0).UTC(), nil
	}
	return time.Time{}, errors.New("cot: bad time " + strconv.Quote(s))
}

func NewUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func New(uid, typ, how string, stale time.Duration) *Event {
	now := time.Now().UTC()
	return &Event{
		Version: "2.0",
		UID:     uid,
		Type:    typ,
		How:     how,
		Time:    now,
		Start:   now,
		Stale:   now.Add(stale),
		Point:   Point{Hae: Unknown, Ce: Unknown, Le: Unknown},
		Detail:  xmltree.New("detail"),
	}
}

func Parse(data []byte) (*Event, error) {
	n, err := xmltree.Parse(data)
	if err != nil {
		return nil, err
	}
	return FromNode(n)
}

func parseFloat(s string, def float64) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return def
	}
	return f
}

func Finite(f, def float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return def
	}
	return f
}

func FromNode(n *xmltree.Node) (*Event, error) {
	if n == nil || n.Name != "event" {
		return nil, ErrNotEvent
	}
	e := &Event{Point: Point{Hae: Unknown, Ce: Unknown, Le: Unknown}}
	for _, a := range n.Attrs {
		switch a.Name {
		case "version":
			e.Version = a.Value
		case "uid":
			e.UID = a.Value
		case "type":
			e.Type = a.Value
		case "how":
			e.How = a.Value
		case "time":
			e.Time, _ = ParseTime(a.Value)
		case "start":
			e.Start, _ = ParseTime(a.Value)
		case "stale":
			e.Stale, _ = ParseTime(a.Value)
		case "access":
			e.Access = a.Value
		case "qos":
			e.QoS = a.Value
		case "opex":
			e.Opex = a.Value
		case "caveat":
			e.Caveat = a.Value
		case "releasableTo", "releaseableTo":
			e.Releasable = a.Value
		default:
			e.Extra = append(e.Extra, a)
		}
	}
	if e.UID == "" {
		return nil, ErrNoUID
	}
	if e.Type == "" {
		return nil, ErrNoType
	}
	seenPoint := false
	for _, c := range n.Children {
		switch c.Name {
		case "point":
			if !seenPoint {
				seenPoint = true
				e.Point = Point{
					Lat: parseFloat(c.Attr("lat"), 0),
					Lon: parseFloat(c.Attr("lon"), 0),
					Hae: parseFloat(c.Attr("hae"), Unknown),
					Ce:  parseFloat(c.Attr("ce"), Unknown),
					Le:  parseFloat(c.Attr("le"), Unknown),
				}
			}
		case "detail":
			if e.Detail == nil {
				e.Detail = c
			} else {
				e.Detail.Children = append(e.Detail.Children, c.Children...)
			}
		}
	}
	e.Normalize()
	return e, nil
}

func (e *Event) Normalize() {
	if e.Version == "" {
		e.Version = "2.0"
	}
	if e.Detail == nil {
		e.Detail = xmltree.New("detail")
	}
	now := time.Now().UTC()
	if e.Time.IsZero() {
		if !e.Start.IsZero() {
			e.Time = e.Start
		} else {
			e.Time = now
		}
	}
	if e.Start.IsZero() {
		e.Start = e.Time
	}
	if e.Stale.IsZero() {
		e.Stale = e.Start.Add(2 * time.Minute)
	}
}

func FormatFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "0.0"
	}
	if f == float64(int64(f)) && f < 1e15 && f > -1e15 {
		return strconv.FormatFloat(f, 'f', 1, 64)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func (e *Event) AppendXML(dst []byte) []byte {
	v := e.Version
	if v == "" {
		v = "2.0"
	}
	attr := func(name, value string) {
		dst = append(dst, ' ')
		dst = append(dst, name...)
		dst = append(dst, '=', '"')
		dst = xmltree.EscapeAttr(dst, value)
		dst = append(dst, '"')
	}
	dst = append(dst, "<event"...)
	attr("version", v)
	attr("uid", e.UID)
	attr("type", e.Type)
	attr("how", e.How)
	attr("time", FormatTime(e.Time))
	attr("start", FormatTime(e.Start))
	attr("stale", FormatTime(e.Stale))
	if e.Access != "" {
		attr("access", e.Access)
	}
	if e.QoS != "" {
		attr("qos", e.QoS)
	}
	if e.Opex != "" {
		attr("opex", e.Opex)
	}
	if e.Caveat != "" {
		attr("caveat", e.Caveat)
	}
	if e.Releasable != "" {
		attr("releasableTo", e.Releasable)
	}
	for _, a := range e.Extra {
		attr(a.Name, a.Value)
	}
	dst = append(dst, "><point"...)
	attr("lat", FormatFloat(e.Point.Lat))
	attr("lon", FormatFloat(e.Point.Lon))
	attr("hae", FormatFloat(e.Point.Hae))
	attr("ce", FormatFloat(e.Point.Ce))
	attr("le", FormatFloat(e.Point.Le))
	dst = append(dst, "/>"...)
	if e.Detail != nil && (len(e.Detail.Children) > 0 || e.Detail.Text != "" || len(e.Detail.Attrs) > 0) {
		d := e.Detail
		if d.Name != "detail" {
			d = &xmltree.Node{Name: "detail", Attrs: d.Attrs, Children: d.Children, Text: d.Text}
		}
		dst = d.AppendXML(dst)
	} else {
		dst = append(dst, "<detail/>"...)
	}
	return append(dst, "</event>"...)
}

func (e *Event) XML() []byte {
	return e.AppendXML(make([]byte, 0, 512))
}

func (e *Event) String() string { return string(e.XML()) }

func (e *Event) Clone() *Event {
	c := *e
	if e.Extra != nil {
		c.Extra = append([]xmltree.Attr(nil), e.Extra...)
	}
	c.Detail = e.Detail.Clone()
	if c.Detail == nil {
		c.Detail = xmltree.New("detail")
	}
	return &c
}

func (e *Event) D(path ...string) *xmltree.Node {
	if e.Detail == nil {
		return nil
	}
	return e.Detail.Find(path...)
}

func (e *Event) Callsign() string {
	if c := e.D("contact"); c != nil {
		return c.Attr("callsign")
	}
	return ""
}

func (e *Event) Endpoint() string {
	if c := e.D("contact"); c != nil {
		return c.Attr("endpoint")
	}
	return ""
}

func (e *Event) Team() (name, role string) {
	if g := e.D("__group"); g != nil {
		return g.Attr("name"), g.Attr("role")
	}
	return "", ""
}

func (e *Event) Takv() (device, platform, os, version string) {
	if t := e.D("takv"); t != nil {
		return t.Attr("device"), t.Attr("platform"), t.Attr("os"), t.Attr("version")
	}
	return "", "", "", ""
}

func (e *Event) Remarks() string {
	if r := e.D("remarks"); r != nil {
		return r.Text
	}
	return ""
}

func (e *Event) Dests() []Dest {
	var out []Dest
	if e.Detail == nil {
		return nil
	}
	for _, m := range e.Detail.All("marti") {
		for _, d := range m.All("dest") {
			x := Dest{UID: d.Attr("uid"), Callsign: d.Attr("callsign"), Mission: d.Attr("mission"), Group: d.Attr("group")}
			if x.UID != "" || x.Callsign != "" || x.Mission != "" || x.Group != "" {
				out = append(out, x)
			}
		}
	}
	return out
}

func (e *Event) Links() []Link {
	if e.Detail == nil {
		return nil
	}
	var out []Link
	for _, l := range e.Detail.All("link") {
		out = append(out, Link{UID: l.Attr("uid"), Type: l.Attr("type"), Relation: l.Attr("relation"), Callsign: l.Attr("parent_callsign")})
	}
	return out
}

func (e *Event) SetDests(dests []Dest) {
	e.Detail.RemoveAll("marti")
	if len(dests) == 0 {
		return
	}
	m := e.Detail.AddNew("marti")
	for _, d := range dests {
		n := m.AddNew("dest")
		if d.UID != "" {
			n.SetAttr("uid", d.UID)
		}
		if d.Callsign != "" {
			n.SetAttr("callsign", d.Callsign)
		}
		if d.Mission != "" {
			n.SetAttr("mission", d.Mission)
		}
		if d.Group != "" {
			n.SetAttr("group", d.Group)
		}
	}
}

func (e *Event) IsStale(now time.Time) bool {
	return !e.Stale.IsZero() && now.After(e.Stale)
}

func (e *Event) Is(prefix string) bool { return strings.HasPrefix(e.Type, prefix) }

func (e *Event) IsPing() bool { return e.Type == "t-x-c-t" }

func (e *Event) IsControl() bool { return strings.HasPrefix(e.Type, "t-x-") }

func (e *Event) IsChat() bool { return strings.HasPrefix(e.Type, "b-t-f") }

func (e *Event) IsDelete() bool { return e.Type == "t-x-d-d" }

func (e *Event) IsSA() bool {
	if !strings.HasPrefix(e.Type, "a-") {
		return false
	}
	c := e.D("contact")
	return c != nil && (c.HasAttr("endpoint") || e.D("takv") != nil)
}

func (e *Event) IsEmergency() bool {
	return e.D("emergency") != nil && strings.HasPrefix(e.Type, "b-a-")
}

func (e *Event) EmergencyCancel() bool {
	em := e.D("emergency")
	if em == nil {
		return e.Type == "b-a-o-can"
	}
	return strings.EqualFold(em.Attr("cancel"), "true") || e.Type == "b-a-o-can"
}

func (e *Event) FlowTag(key string) string {
	if f := e.D("_flow-tags_"); f != nil {
		return f.Attr(key)
	}
	return ""
}

func (e *Event) AddFlowTag(key string, t time.Time) {
	f := e.D("_flow-tags_")
	if f == nil {
		f = e.Detail.AddNew("_flow-tags_")
	}
	f.SetAttr(key, FormatTime(t))
}

func Ping(uid string) *Event {
	e := New(uid, "t-x-c-t", "h-g-i-g-o", 20*time.Second)
	return e
}

func Pong() *Event {
	return New("takPong", "t-x-c-t-r", "h-g-i-g-o", 20*time.Second)
}

func DeleteFor(uid, typ string) *Event {
	e := New(NewUID(), "t-x-d-d", "h-g-i-g-o", 20*time.Second)
	l := e.Detail.AddNew("link", "uid", uid, "relation", "p-p")
	if typ != "" {
		l.SetAttr("type", typ)
	}
	return e
}

func Chat(senderUID, senderCallsign, room, roomID, message string, dests []Dest) *Event {
	msgID := NewUID()
	e := New("GeoChat."+senderUID+"."+roomID+"."+msgID, "b-t-f", "h-g-i-g-o", 24*time.Hour)
	c := e.Detail.AddNew("__chat", "parent", "RootContactGroup", "groupOwner", "false", "messageId", msgID,
		"chatroom", room, "id", roomID, "senderCallsign", senderCallsign)
	c.AddNew("chatgrp", "uid0", senderUID, "uid1", roomID, "id", roomID)
	e.Detail.AddNew("link", "uid", senderUID, "type", "a-f-G-U-C", "relation", "p-p")
	r := e.Detail.AddNew("remarks", "source", "BAO.F.ATAK."+senderUID, "to", roomID, "time", FormatTime(e.Time))
	r.Text = message
	e.Detail.AddNew("__serverdestination", "destinations", "0.0.0.0:4242:tcp:"+senderUID)
	if len(dests) > 0 {
		e.SetDests(dests)
	}
	return e
}
