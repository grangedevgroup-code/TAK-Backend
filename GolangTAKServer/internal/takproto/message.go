package takproto

import (
	"errors"
	"strconv"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

const Magic = 0xbf

const Version = 1

var ErrNoEvent = errors.New("takproto: message has no event")

type Control struct {
	MinVersion uint32
	MaxVersion uint32
	ContactUID string
}

type Message struct {
	Event          *cot.Event
	Control        *Control
	SubmissionTime uint64
	CreationTime   uint64
}

func millis(t time.Time) uint64 {
	if t.IsZero() || t.UnixMilli() < 0 {
		return 0
	}
	return uint64(t.UnixMilli())
}

func Marshal(e *cot.Event) []byte {
	ev := marshalEvent(e)
	b := make([]byte, 0, len(ev)+8)
	return appendBytes(b, 2, ev)
}

func MarshalControl(c Control) []byte {
	var cb []byte
	cb = appendUint(cb, 1, uint64(c.MinVersion))
	cb = appendUint(cb, 2, uint64(c.MaxVersion))
	cb = appendString(cb, 3, c.ContactUID)
	return appendBytes(nil, 1, cb)
}

func marshalEvent(e *cot.Event) []byte {
	b := make([]byte, 0, 256)
	b = appendString(b, 1, e.Type)
	b = appendString(b, 2, e.Access)
	b = appendString(b, 3, e.QoS)
	b = appendString(b, 4, e.Opex)
	b = appendString(b, 5, e.UID)
	b = appendUint(b, 6, millis(e.Time))
	b = appendUint(b, 7, millis(e.Start))
	b = appendUint(b, 8, millis(e.Stale))
	b = appendString(b, 9, e.How)
	b = appendDouble(b, 10, e.Point.Lat)
	b = appendDouble(b, 11, e.Point.Lon)
	b = appendDouble(b, 12, e.Point.Hae)
	b = appendDouble(b, 13, e.Point.Ce)
	b = appendDouble(b, 14, e.Point.Le)
	b = appendBytes(b, 15, marshalDetail(e.Detail))
	b = appendString(b, 16, e.Caveat)
	b = appendString(b, 17, e.Releasable)
	return b
}

func onlyAttrs(n *xmltree.Node, required []string, optional ...string) bool {
	if len(n.Children) > 0 || n.Text != "" {
		return false
	}
	for _, r := range required {
		if !n.HasAttr(r) {
			return false
		}
	}
	for _, a := range n.Attrs {
		ok := false
		for _, r := range required {
			if a.Name == r {
				ok = true
				break
			}
		}
		for _, o := range optional {
			if a.Name == o {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	seen := map[string]bool{}
	for _, a := range n.Attrs {
		if seen[a.Name] {
			return false
		}
		seen[a.Name] = true
	}
	return true
}

func marshalDetail(d *xmltree.Node) []byte {
	if d == nil {
		return nil
	}
	counts := map[string]int{}
	for _, c := range d.Children {
		counts[c.Name]++
	}
	var contact, group, ploc, status, takv, track []byte
	var rest []byte
	if d.Text != "" {
		rest = xmltree.EscapeText(rest, d.Text)
	}
	for _, c := range d.Children {
		if counts[c.Name] == 1 {
			switch c.Name {
			case "contact":
				if onlyAttrs(c, []string{"callsign"}, "endpoint") {
					contact = appendString(contact, 1, c.Attr("endpoint"))
					contact = appendString(contact, 2, c.Attr("callsign"))
					continue
				}
			case "__group":
				if onlyAttrs(c, []string{"name", "role"}) {
					group = appendString(group, 1, c.Attr("name"))
					group = appendString(group, 2, c.Attr("role"))
					continue
				}
			case "precisionlocation":
				if onlyAttrs(c, []string{"geopointsrc", "altsrc"}) {
					ploc = appendString(ploc, 1, c.Attr("geopointsrc"))
					ploc = appendString(ploc, 2, c.Attr("altsrc"))
					continue
				}
			case "status":
				if onlyAttrs(c, []string{"battery"}) {
					if v, err := strconv.ParseUint(c.Attr("battery"), 10, 32); err == nil {
						status = appendUint(status, 1, v)
						continue
					}
				}
			case "takv":
				if onlyAttrs(c, []string{"device", "platform", "os", "version"}) {
					takv = appendString(takv, 1, c.Attr("device"))
					takv = appendString(takv, 2, c.Attr("platform"))
					takv = appendString(takv, 3, c.Attr("os"))
					takv = appendString(takv, 4, c.Attr("version"))
					continue
				}
			case "track":
				if onlyAttrs(c, []string{"speed", "course"}) {
					sp, err1 := strconv.ParseFloat(c.Attr("speed"), 64)
					co, err2 := strconv.ParseFloat(c.Attr("course"), 64)
					if err1 == nil && err2 == nil && cot.Finite(sp, 0) == sp && cot.Finite(co, 0) == co {
						track = appendDouble(track, 1, sp)
						track = appendDouble(track, 2, co)
						continue
					}
				}
			}
		}
		rest = c.AppendXML(rest)
	}
	var b []byte
	if len(rest) > 0 {
		b = appendBytes(b, 1, rest)
	}
	if contact != nil {
		b = appendBytes(b, 2, contact)
	}
	if group != nil {
		b = appendBytes(b, 3, group)
	}
	if ploc != nil {
		b = appendBytes(b, 4, ploc)
	}
	if status != nil {
		b = appendBytes(b, 5, status)
	}
	if takv != nil {
		b = appendBytes(b, 6, takv)
	}
	if track != nil {
		b = appendBytes(b, 7, track)
	}
	return b
}

func Unmarshal(b []byte) (*Message, error) {
	m := &Message{}
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			if f.wire != wireBytes {
				return ErrWireType
			}
			c, err := unmarshalControl(f.bytes)
			if err != nil {
				return err
			}
			m.Control = c
		case 2:
			if f.wire != wireBytes {
				return ErrWireType
			}
			e, err := unmarshalEvent(f.bytes)
			if err != nil {
				return err
			}
			m.Event = e
		case 3:
			m.SubmissionTime = f.uint()
		case 4:
			m.CreationTime = f.uint()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func UnmarshalEvent(b []byte) (*cot.Event, error) {
	m, err := Unmarshal(b)
	if err != nil {
		return nil, err
	}
	if m.Event == nil {
		return nil, ErrNoEvent
	}
	return m.Event, nil
}

func unmarshalControl(b []byte) (*Control, error) {
	c := &Control{}
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			c.MinVersion = uint32(f.uint())
		case 2:
			c.MaxVersion = uint32(f.uint())
		case 3:
			c.ContactUID = f.str()
		}
		return nil
	})
	return c, err
}

func fromMillis(v uint64) time.Time {
	if v == 0 || v > 1<<62 {
		return time.Time{}
	}
	return time.UnixMilli(int64(v)).UTC()
}

func unmarshalEvent(b []byte) (*cot.Event, error) {
	e := &cot.Event{Version: "2.0", Point: cot.Point{}}
	var detail []byte
	hasDetail := false
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			e.Type = f.str()
		case 2:
			e.Access = f.str()
		case 3:
			e.QoS = f.str()
		case 4:
			e.Opex = f.str()
		case 5:
			e.UID = f.str()
		case 6:
			e.Time = fromMillis(f.uint())
		case 7:
			e.Start = fromMillis(f.uint())
		case 8:
			e.Stale = fromMillis(f.uint())
		case 9:
			e.How = f.str()
		case 10:
			e.Point.Lat = cot.Finite(f.double(), 0)
		case 11:
			e.Point.Lon = cot.Finite(f.double(), 0)
		case 12:
			e.Point.Hae = cot.Finite(f.double(), cot.Unknown)
		case 13:
			e.Point.Ce = cot.Finite(f.double(), cot.Unknown)
		case 14:
			e.Point.Le = cot.Finite(f.double(), cot.Unknown)
		case 15:
			if f.wire != wireBytes {
				return ErrWireType
			}
			detail = f.bytes
			hasDetail = true
		case 16:
			e.Caveat = f.str()
		case 17:
			e.Releasable = f.str()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if e.UID == "" {
		return nil, cot.ErrNoUID
	}
	if e.Type == "" {
		return nil, cot.ErrNoType
	}
	e.Detail = xmltree.New("detail")
	if hasDetail {
		if err := unmarshalDetail(detail, e.Detail); err != nil {
			return nil, err
		}
	}
	e.Normalize()
	return e, nil
}

func unmarshalDetail(b []byte, d *xmltree.Node) error {
	var xmlDetail []byte
	typed := map[string]*xmltree.Node{}
	err := eachField(b, func(f field) error {
		if f.num >= 1 && f.num <= 7 && f.wire != wireBytes {
			return ErrWireType
		}
		switch f.num {
		case 1:
			xmlDetail = f.bytes
		case 2:
			n := xmltree.New("contact")
			var endpoint, callsign string
			if err := eachField(f.bytes, func(g field) error {
				switch g.num {
				case 1:
					endpoint = g.str()
				case 2:
					callsign = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			n.SetAttr("callsign", callsign)
			if endpoint != "" {
				n.SetAttr("endpoint", endpoint)
			}
			typed["contact"] = n
		case 3:
			var name, role string
			if err := eachField(f.bytes, func(g field) error {
				switch g.num {
				case 1:
					name = g.str()
				case 2:
					role = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			typed["__group"] = xmltree.New("__group", "name", name, "role", role)
		case 4:
			var gp, alt string
			if err := eachField(f.bytes, func(g field) error {
				switch g.num {
				case 1:
					gp = g.str()
				case 2:
					alt = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			typed["precisionlocation"] = xmltree.New("precisionlocation", "geopointsrc", gp, "altsrc", alt)
		case 5:
			var battery uint64
			if err := eachField(f.bytes, func(g field) error {
				if g.num == 1 {
					battery = g.uint()
				}
				return nil
			}); err != nil {
				return err
			}
			typed["status"] = xmltree.New("status", "battery", strconv.FormatUint(uint64(uint32(battery)), 10))
		case 6:
			var dev, plat, os, ver string
			if err := eachField(f.bytes, func(g field) error {
				switch g.num {
				case 1:
					dev = g.str()
				case 2:
					plat = g.str()
				case 3:
					os = g.str()
				case 4:
					ver = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			typed["takv"] = xmltree.New("takv", "device", dev, "platform", plat, "os", os, "version", ver)
		case 7:
			var speed, course float64
			if err := eachField(f.bytes, func(g field) error {
				switch g.num {
				case 1:
					speed = cot.Finite(g.double(), 0)
				case 2:
					course = cot.Finite(g.double(), 0)
				}
				return nil
			}); err != nil {
				return err
			}
			typed["track"] = xmltree.New("track", "speed", cot.FormatFloat(speed), "course", cot.FormatFloat(course))
		}
		return nil
	})
	if err != nil {
		return err
	}
	var extra []*xmltree.Node
	var text string
	if len(xmlDetail) > 0 {
		wrapped := make([]byte, 0, len(xmlDetail)+17)
		wrapped = append(wrapped, "<detail>"...)
		wrapped = append(wrapped, xmlDetail...)
		wrapped = append(wrapped, "</detail>"...)
		if n, err := xmltree.Parse(wrapped); err == nil {
			extra = n.Children
			text = n.Text
		}
	}
	for _, name := range []string{"contact", "__group", "precisionlocation", "status", "takv", "track"} {
		n, ok := typed[name]
		if !ok {
			continue
		}
		overridden := false
		for _, x := range extra {
			if x.Name == name {
				overridden = true
				break
			}
		}
		if !overridden {
			d.Add(n)
		}
	}
	d.Children = append(d.Children, extra...)
	d.Text = text
	return nil
}
