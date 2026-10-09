package takproto

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

const (
	CRUDCreate = 1
	CRUDRead   = 2
	CRUDUpdate = 3
	CRUDDelete = 4
)

type ContactEntry struct {
	Operation     int
	UID           string
	Callsign      string
	Phone         string
	Sip           string
	DirectConnect string
}

type Provenance struct {
	ServerID   string
	ServerName string
}

type FedEvent struct {
	Event       *cot.Event
	Contact     *ContactEntry
	Groups      []string
	Provenance  []Provenance
	MaxHops     int64
	CurrentHops int64
	HopLimits   []byte
}

func appendInt(b []byte, field int, v int64) []byte {
	if v == 0 {
		return b
	}
	b = appendTag(b, field, wireVarint)
	return AppendVarint(b, uint64(v))
}

func appendRepeated(b []byte, field int, vals []string) []byte {
	for _, v := range vals {
		b = appendTag(b, field, wireBytes)
		b = AppendVarint(b, uint64(len(v)))
		b = append(b, v...)
	}
	return b
}

func millisInt(e *cot.Event, which int) int64 {
	switch which {
	case 0:
		return int64(millis(e.Time))
	case 1:
		return int64(millis(e.Start))
	}
	return int64(millis(e.Stale))
}

func MarshalGeoEvent(e *cot.Event) []byte {
	var b []byte
	b = appendInt(b, 1, millisInt(e, 0))
	b = appendInt(b, 2, millisInt(e, 1))
	b = appendInt(b, 3, millisInt(e, 2))
	b = appendDouble(b, 4, e.Point.Lat)
	b = appendDouble(b, 5, e.Point.Lon)
	b = appendDouble(b, 6, e.Point.Hae)
	b = appendDouble(b, 7, e.Point.Ce)
	b = appendDouble(b, 8, e.Point.Le)
	b = appendString(b, 9, e.UID)
	b = appendString(b, 10, e.Type)
	b = appendString(b, 11, e.How)
	d := e.Detail.Clone()
	if d == nil {
		d = xmltree.New("detail")
	}
	d.Name = "detail"
	var speed, course float64
	var battery int64
	var ploc, palt string
	if tr := d.Child("track"); tr != nil && tr.HasAttr("speed") && tr.HasAttr("course") {
		d.Remove(tr)
		speed, _ = strconv.ParseFloat(tr.Attr("speed"), 64)
		course, _ = strconv.ParseFloat(tr.Attr("course"), 64)
	}
	if st := d.Child("status"); st != nil && st.HasAttr("battery") && !st.HasAttr("readiness") {
		d.Remove(st)
		v, _ := strconv.ParseFloat(st.Attr("battery"), 64)
		battery = int64(v)
	}
	if pl := d.Child("precisionlocation"); pl != nil && pl.HasAttr("geopointsrc") && pl.HasAttr("altsrc") {
		d.Remove(pl)
		ploc, palt = pl.Attr("geopointsrc"), pl.Attr("altsrc")
	}
	var image []byte
	if im := d.Child("image"); im != nil {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(im.Text)); err == nil && len(raw) > 0 {
			image = raw
			im.Text = ""
		}
	}
	var ptpUIDs, ptpCallsigns, missions []string
	for _, dest := range e.Dests() {
		if dest.UID != "" {
			ptpUIDs = append(ptpUIDs, dest.UID)
		}
		if dest.Callsign != "" {
			ptpCallsigns = append(ptpCallsigns, dest.Callsign)
		}
		if dest.Mission != "" {
			missions = append(missions, dest.Mission)
		}
	}
	b = appendString(b, 12, d.String())
	b = appendInt(b, 13, battery)
	b = appendString(b, 14, ploc)
	b = appendString(b, 15, palt)
	b = appendDouble(b, 20, cot.Finite(speed, 0))
	b = appendDouble(b, 21, cot.Finite(course, 0))
	if image != nil {
		b = appendBytes(b, 22, MarshalBlob(Blob{Type: BlobImage, Data: image}))
	}
	b = appendRepeated(b, 23, ptpUIDs)
	b = appendRepeated(b, 24, ptpCallsigns)
	b = appendRepeated(b, 26, missions)
	b = appendString(b, 27, e.Access)
	b = appendString(b, 28, e.Caveat)
	b = appendString(b, 29, e.Releasable)
	return b
}

func MarshalFed(f FedEvent) []byte {
	var b []byte
	if f.Event != nil {
		b = appendBytes(b, 1, MarshalGeoEvent(f.Event))
	}
	if c := f.Contact; c != nil {
		var cb []byte
		cb = appendInt(cb, 1, int64(c.Operation))
		cb = appendString(cb, 2, c.UID)
		cb = appendString(cb, 3, c.Callsign)
		cb = appendString(cb, 4, c.Phone)
		cb = appendString(cb, 5, c.Sip)
		cb = appendString(cb, 6, c.DirectConnect)
		b = appendBytes(b, 2, cb)
	}
	b = appendRepeated(b, 3, f.Groups)
	for _, p := range f.Provenance {
		var pb []byte
		pb = appendString(pb, 1, p.ServerID)
		pb = appendString(pb, 2, p.ServerName)
		b = appendBytes(b, 4, pb)
	}
	if f.MaxHops > 0 || f.CurrentHops > 0 {
		var hb []byte
		hb = appendInt(hb, 1, f.MaxHops)
		hb = appendInt(hb, 2, f.CurrentHops)
		b = appendBytes(b, 5, hb)
	}
	if len(f.HopLimits) > 0 {
		b = appendBytes(b, 6, f.HopLimits)
	}
	return b
}

type geo struct {
	send, start, stale              int64
	lat, lon, hae, ce, le           float64
	uid, typ, how, other            string
	battery                         int64
	ploc, palt                      string
	speed, course                   float64
	ptpUIDs, ptpCallsigns, missions []string
	access, caveat, releasable      string
	image                           []byte
}

func UnmarshalFed(b []byte) (*FedEvent, error) {
	f := &FedEvent{}
	err := eachField(b, func(fd field) error {
		switch fd.num {
		case 1:
			if fd.wire != wireBytes {
				return ErrWireType
			}
			e, err := unmarshalGeo(fd.bytes)
			if err != nil {
				return err
			}
			f.Event = e
		case 2:
			if fd.wire != wireBytes {
				return ErrWireType
			}
			c := &ContactEntry{}
			if err := eachField(fd.bytes, func(g field) error {
				switch g.num {
				case 1:
					c.Operation = int(g.uint())
				case 2:
					c.UID = g.str()
				case 3:
					c.Callsign = g.str()
				case 4:
					c.Phone = g.str()
				case 5:
					c.Sip = g.str()
				case 6:
					c.DirectConnect = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			f.Contact = c
		case 3:
			f.Groups = append(f.Groups, fd.str())
		case 4:
			var p Provenance
			if err := eachField(fd.bytes, func(g field) error {
				switch g.num {
				case 1:
					p.ServerID = g.str()
				case 2:
					p.ServerName = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			f.Provenance = append(f.Provenance, p)
		case 5:
			if err := eachField(fd.bytes, func(g field) error {
				switch g.num {
				case 1:
					f.MaxHops = int64(g.uint())
				case 2:
					f.CurrentHops = int64(g.uint())
				}
				return nil
			}); err != nil {
				return err
			}
		case 6:
			if fd.wire == wireBytes {
				f.HopLimits = append([]byte(nil), fd.bytes...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

func unmarshalGeo(b []byte) (*cot.Event, error) {
	var g geo
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			g.send = int64(f.uint())
		case 2:
			g.start = int64(f.uint())
		case 3:
			g.stale = int64(f.uint())
		case 4:
			g.lat = f.double()
		case 5:
			g.lon = f.double()
		case 6:
			g.hae = f.double()
		case 7:
			g.ce = f.double()
		case 8:
			g.le = f.double()
		case 9:
			g.uid = f.str()
		case 10:
			g.typ = f.str()
		case 11:
			g.how = f.str()
		case 12:
			g.other = f.str()
		case 13:
			g.battery = int64(int32(f.uint()))
		case 14:
			g.ploc = f.str()
		case 15:
			g.palt = f.str()
		case 20:
			g.speed = f.double()
		case 21:
			g.course = f.double()
		case 22:
			if f.wire == wireBytes {
				if bl, err := UnmarshalBlob(f.bytes); err == nil && bl.Type == BlobImage {
					g.image = bl.Data
				}
			}
		case 23:
			g.ptpUIDs = append(g.ptpUIDs, f.str())
		case 24:
			g.ptpCallsigns = append(g.ptpCallsigns, f.str())
		case 26:
			g.missions = append(g.missions, f.str())
		case 27:
			g.access = f.str()
		case 28:
			g.caveat = f.str()
		case 29:
			g.releasable = f.str()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if g.uid == "" {
		return nil, cot.ErrNoUID
	}
	if g.typ == "" {
		return nil, cot.ErrNoType
	}
	e := &cot.Event{Version: "2.0", UID: g.uid, Type: g.typ, How: g.how,
		Time: fromMillis(uint64(max(g.send, 0))), Start: fromMillis(uint64(max(g.start, 0))), Stale: fromMillis(uint64(max(g.stale, 0))),
		Access: g.access, Caveat: g.caveat, Releasable: g.releasable,
		Point: cot.Point{Lat: cot.Finite(g.lat, 0), Lon: cot.Finite(g.lon, 0), Hae: cot.Finite(g.hae, cot.Unknown), Ce: cot.Finite(g.ce, cot.Unknown), Le: cot.Finite(g.le, cot.Unknown)}}
	d := xmltree.New("detail")
	if strings.TrimSpace(g.other) != "" {
		if n, err := xmltree.Parse([]byte(g.other)); err == nil {
			if n.Name == "detail" {
				d = n
			} else {
				d.Add(n)
			}
		}
	}
	if d.Child("track") == nil {
		d.AddNew("track", "speed", cot.FormatFloat(cot.Finite(g.speed, 0)), "course", cot.FormatFloat(cot.Finite(g.course, 0)))
	}
	if d.Child("status") == nil && g.battery > 0 {
		d.AddNew("status", "battery", strconv.FormatInt(g.battery, 10))
	}
	if d.Child("precisionlocation") == nil && (g.ploc != "" || g.palt != "") {
		pl := d.AddNew("precisionlocation")
		if g.ploc != "" {
			pl.SetAttr("geopointsrc", g.ploc)
		}
		if g.palt != "" {
			pl.SetAttr("altsrc", g.palt)
		}
	}
	if im := d.Child("image"); im != nil && len(g.image) > 0 {
		im.Text = base64.StdEncoding.EncodeToString(g.image)
	}
	e.Detail = d
	if len(e.Dests()) == 0 && (len(g.ptpUIDs) > 0 || len(g.ptpCallsigns) > 0 || len(g.missions) > 0) {
		var dests []cot.Dest
		for _, u := range g.ptpUIDs {
			dests = append(dests, cot.Dest{UID: u})
		}
		for _, c := range g.ptpCallsigns {
			dests = append(dests, cot.Dest{Callsign: c})
		}
		for _, m := range g.missions {
			dests = append(dests, cot.Dest{Mission: m})
		}
		e.SetDests(dests)
	}
	e.Normalize()
	return e, nil
}

func FedFrame(payload []byte) []byte {
	n := len(payload)
	out := make([]byte, 4, 4+n)
	out[0], out[1], out[2], out[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	return append(out, payload...)
}
