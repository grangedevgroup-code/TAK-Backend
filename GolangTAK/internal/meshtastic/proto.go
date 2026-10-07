package meshtastic

import (
	"encoding/binary"
	"errors"
	"math"
)

var ErrMalformed = errors.New("meshtastic: malformed message")

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

type field struct {
	num   int
	wire  int
	u     uint64
	bytes []byte
}

func readVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * uint(i))
		if b[i] < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, ErrMalformed
}

func fields(b []byte, fn func(f field)) error {
	for len(b) > 0 {
		key, n, err := readVarint(b)
		if err != nil {
			return err
		}
		b = b[n:]
		f := field{num: int(key >> 3), wire: int(key & 7)}
		if f.num <= 0 {
			return ErrMalformed
		}
		switch f.wire {
		case wireVarint:
			v, n, err := readVarint(b)
			if err != nil {
				return err
			}
			f.u = v
			b = b[n:]
		case wireFixed64:
			if len(b) < 8 {
				return ErrMalformed
			}
			f.u = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case wireFixed32:
			if len(b) < 4 {
				return ErrMalformed
			}
			f.u = uint64(binary.LittleEndian.Uint32(b))
			b = b[4:]
		case wireBytes:
			l, n, err := readVarint(b)
			if err != nil {
				return err
			}
			b = b[n:]
			if l > uint64(len(b)) {
				return ErrMalformed
			}
			f.bytes = b[:l]
			b = b[l:]
		default:
			return ErrMalformed
		}
		fn(f)
	}
	return nil
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func appendTag(b []byte, num, wire int) []byte { return appendVarint(b, uint64(num)<<3|uint64(wire)) }

func putVarint(b []byte, num int, v uint64) []byte {
	if v == 0 {
		return b
	}
	return appendVarint(appendTag(b, num, wireVarint), v)
}

func putInt32(b []byte, num int, v int32) []byte {
	if v == 0 {
		return b
	}
	return appendVarint(appendTag(b, num, wireVarint), uint64(int64(v)))
}

func putFixed32(b []byte, num int, v uint32) []byte {
	if v == 0 {
		return b
	}
	return binary.LittleEndian.AppendUint32(appendTag(b, num, wireFixed32), v)
}

func putFixed32Always(b []byte, num int, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(appendTag(b, num, wireFixed32), v)
}

func putBytes(b []byte, num int, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = appendTag(b, num, wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func putString(b []byte, num int, s string) []byte { return putBytes(b, num, []byte(s)) }

func putBool(b []byte, num int, v bool) []byte {
	if !v {
		return b
	}
	return append(appendTag(b, num, wireVarint), 1)
}

type Envelope struct {
	Packet    *Packet
	ChannelID string
	GatewayID string
}

type Packet struct {
	From      uint32
	To        uint32
	Channel   uint32
	ID        uint32
	RxTime    uint32
	HopLimit  uint32
	HopStart  uint32
	WantAck   bool
	ViaMQTT   bool
	Encrypted []byte
	Decoded   *Data
}

type Data struct {
	Portnum   uint32
	Payload   []byte
	Dest      uint32
	Source    uint32
	RequestID uint32
	ReplyID   uint32
	Emoji     uint32
}

type Position struct {
	HasPosition bool
	LatI        int32
	LonI        int32
	Altitude    int32
	HasAltitude bool
	Time        uint32
	GroundSpeed uint32
	HasSpeed    bool
	GroundTrack uint32
	HasTrack    bool
	Sats        uint32
}

type User struct {
	ID        string
	LongName  string
	ShortName string
	HWModel   uint32
	Role      uint32
}

type DeviceMetrics struct {
	Battery    uint32
	HasBattery bool
	Voltage    float32
	Uptime     uint32
}

type TAKPacket struct {
	Compressed     bool
	Callsign       string
	DeviceCallsign string
	Role           uint32
	Team           uint32
	Battery        uint32
	PLI            *PLI
	Chat           *GeoChat
	Detail         []byte
}

type PLI struct {
	LatI     int32
	LonI     int32
	Altitude int32
	Speed    uint32
	Course   uint32
}

type GeoChat struct {
	Message    string
	To         string
	ToCallsign string
}

func ParseEnvelope(b []byte) (*Envelope, error) {
	e := &Envelope{}
	var perr error
	err := fields(b, func(f field) {
		switch f.num {
		case 1:
			if f.wire == wireBytes {
				e.Packet, perr = ParsePacket(f.bytes)
			}
		case 2:
			e.ChannelID = string(f.bytes)
		case 3:
			e.GatewayID = string(f.bytes)
		}
	})
	if err != nil {
		return nil, err
	}
	if perr != nil {
		return nil, perr
	}
	if e.Packet == nil {
		return nil, ErrMalformed
	}
	return e, nil
}

func (e *Envelope) Marshal() []byte {
	var b []byte
	if e.Packet != nil {
		b = putBytes(b, 1, e.Packet.Marshal())
	}
	b = putString(b, 2, e.ChannelID)
	return putString(b, 3, e.GatewayID)
}

func ParsePacket(b []byte) (*Packet, error) {
	p := &Packet{}
	var derr error
	err := fields(b, func(f field) {
		switch f.num {
		case 1:
			p.From = uint32(f.u)
		case 2:
			p.To = uint32(f.u)
		case 3:
			p.Channel = uint32(f.u)
		case 4:
			if f.wire == wireBytes {
				p.Decoded, derr = ParseData(f.bytes)
			}
		case 5:
			p.Encrypted = append([]byte(nil), f.bytes...)
		case 6:
			p.ID = uint32(f.u)
		case 7:
			p.RxTime = uint32(f.u)
		case 9:
			p.HopLimit = uint32(f.u)
		case 10:
			p.WantAck = f.u != 0
		case 14:
			p.ViaMQTT = f.u != 0
		case 15:
			p.HopStart = uint32(f.u)
		}
	})
	if err != nil {
		return nil, err
	}
	return p, derr
}

func (p *Packet) Marshal() []byte {
	var b []byte
	b = putFixed32Always(b, 1, p.From)
	b = putFixed32Always(b, 2, p.To)
	b = putVarint(b, 3, uint64(p.Channel))
	if p.Decoded != nil {
		b = putBytes(b, 4, p.Decoded.Marshal())
	} else {
		b = putBytes(b, 5, p.Encrypted)
	}
	b = putFixed32(b, 6, p.ID)
	b = putFixed32(b, 7, p.RxTime)
	b = putVarint(b, 9, uint64(p.HopLimit))
	b = putBool(b, 10, p.WantAck)
	b = putBool(b, 14, p.ViaMQTT)
	return putVarint(b, 15, uint64(p.HopStart))
}

func ParseData(b []byte) (*Data, error) {
	d := &Data{}
	err := fields(b, func(f field) {
		switch f.num {
		case 1:
			d.Portnum = uint32(f.u)
		case 2:
			d.Payload = append([]byte(nil), f.bytes...)
		case 4:
			d.Dest = uint32(f.u)
		case 5:
			d.Source = uint32(f.u)
		case 6:
			d.RequestID = uint32(f.u)
		case 7:
			d.ReplyID = uint32(f.u)
		case 8:
			d.Emoji = uint32(f.u)
		}
	})
	return d, err
}

func (d *Data) Marshal() []byte {
	var b []byte
	b = putVarint(b, 1, uint64(d.Portnum))
	b = putBytes(b, 2, d.Payload)
	b = putFixed32(b, 4, d.Dest)
	b = putFixed32(b, 5, d.Source)
	b = putFixed32(b, 6, d.RequestID)
	b = putFixed32(b, 7, d.ReplyID)
	return putFixed32(b, 8, d.Emoji)
}

func ParsePosition(b []byte) (*Position, error) {
	p := &Position{}
	hasLat, hasLon := false, false
	err := fields(b, func(f field) {
		switch f.num {
		case 1:
			p.LatI, hasLat = int32(uint32(f.u)), true
		case 2:
			p.LonI, hasLon = int32(uint32(f.u)), true
		case 3:
			p.Altitude, p.HasAltitude = int32(f.u), true
		case 4:
			p.Time = uint32(f.u)
		case 15:
			p.GroundSpeed, p.HasSpeed = uint32(f.u), true
		case 16:
			p.GroundTrack, p.HasTrack = uint32(f.u), true
		case 19:
			p.Sats = uint32(f.u)
		}
	})
	p.HasPosition = hasLat && hasLon && !(p.LatI == 0 && p.LonI == 0)
	return p, err
}

func (p *Position) Lat() float64 { return float64(p.LatI) / 1e7 }

func (p *Position) Lon() float64 { return float64(p.LonI) / 1e7 }

func (p *Position) Course() (float64, bool) {
	if !p.HasTrack {
		return 0, false
	}
	if p.GroundTrack > 36000 {
		return math.Mod(float64(p.GroundTrack)/1e5, 360), true
	}
	return math.Mod(float64(p.GroundTrack)/100, 360), true
}

func (p *Position) Marshal() []byte {
	var b []byte
	b = putFixed32Always(b, 1, uint32(p.LatI))
	b = putFixed32Always(b, 2, uint32(p.LonI))
	b = putInt32(b, 3, p.Altitude)
	b = putFixed32(b, 4, p.Time)
	b = putVarint(b, 15, uint64(p.GroundSpeed))
	return putVarint(b, 16, uint64(p.GroundTrack))
}

func ParseUser(b []byte) (*User, error) {
	u := &User{}
	err := fields(b, func(f field) {
		switch f.num {
		case 1:
			u.ID = string(f.bytes)
		case 2:
			u.LongName = string(f.bytes)
		case 3:
			u.ShortName = string(f.bytes)
		case 5:
			u.HWModel = uint32(f.u)
		case 7:
			u.Role = uint32(f.u)
		}
	})
	return u, err
}

func (u *User) Marshal() []byte {
	var b []byte
	b = putString(b, 1, u.ID)
	b = putString(b, 2, u.LongName)
	b = putString(b, 3, u.ShortName)
	b = putVarint(b, 5, uint64(u.HWModel))
	return putVarint(b, 7, uint64(u.Role))
}

func ParseDeviceMetrics(telemetry []byte) (*DeviceMetrics, error) {
	var dm *DeviceMetrics
	var inner error
	err := fields(telemetry, func(f field) {
		if f.num != 2 || f.wire != wireBytes {
			return
		}
		dm = &DeviceMetrics{}
		inner = fields(f.bytes, func(g field) {
			switch g.num {
			case 1:
				dm.Battery, dm.HasBattery = uint32(g.u), true
			case 2:
				dm.Voltage = math.Float32frombits(uint32(g.u))
			case 5:
				dm.Uptime = uint32(g.u)
			}
		})
	})
	if err != nil {
		return nil, err
	}
	return dm, inner
}

func ParseTAK(b []byte) (*TAKPacket, error) {
	t := &TAKPacket{}
	var inner error
	sub := func(raw []byte, fn func(f field)) {
		if err := fields(raw, fn); err != nil {
			inner = err
		}
	}
	err := fields(b, func(f field) {
		switch f.num {
		case 1:
			t.Compressed = f.u != 0
		case 2:
			sub(f.bytes, func(g field) {
				switch g.num {
				case 1:
					t.Callsign = string(g.bytes)
				case 2:
					t.DeviceCallsign = string(g.bytes)
				}
			})
		case 3:
			sub(f.bytes, func(g field) {
				switch g.num {
				case 1:
					t.Role = uint32(g.u)
				case 2:
					t.Team = uint32(g.u)
				}
			})
		case 4:
			sub(f.bytes, func(g field) {
				if g.num == 1 {
					t.Battery = uint32(g.u)
				}
			})
		case 5:
			t.PLI = &PLI{}
			sub(f.bytes, func(g field) {
				switch g.num {
				case 1:
					t.PLI.LatI = int32(uint32(g.u))
				case 2:
					t.PLI.LonI = int32(uint32(g.u))
				case 3:
					t.PLI.Altitude = int32(g.u)
				case 4:
					t.PLI.Speed = uint32(g.u)
				case 5:
					t.PLI.Course = uint32(g.u)
				}
			})
		case 6:
			t.Chat = &GeoChat{}
			sub(f.bytes, func(g field) {
				switch g.num {
				case 1:
					t.Chat.Message = string(g.bytes)
				case 2:
					t.Chat.To = string(g.bytes)
				case 3:
					t.Chat.ToCallsign = string(g.bytes)
				}
			})
		case 7:
			t.Detail = append([]byte(nil), f.bytes...)
		}
	})
	if err != nil {
		return nil, err
	}
	return t, inner
}

func (t *TAKPacket) Marshal() []byte {
	var b []byte
	b = putBool(b, 1, t.Compressed)
	var contact []byte
	contact = putString(contact, 1, t.Callsign)
	contact = putString(contact, 2, t.DeviceCallsign)
	b = putBytes(b, 2, contact)
	var group []byte
	group = putVarint(group, 1, uint64(t.Role))
	group = putVarint(group, 2, uint64(t.Team))
	b = putBytes(b, 3, group)
	if t.Battery > 0 {
		b = putBytes(b, 4, putVarint(nil, 1, uint64(t.Battery)))
	}
	if t.PLI != nil {
		var p []byte
		p = putFixed32Always(p, 1, uint32(t.PLI.LatI))
		p = putFixed32Always(p, 2, uint32(t.PLI.LonI))
		p = putInt32(p, 3, t.PLI.Altitude)
		p = putVarint(p, 4, uint64(t.PLI.Speed))
		p = putVarint(p, 5, uint64(t.PLI.Course))
		b = putBytes(b, 5, p)
	} else if t.Chat != nil {
		var c []byte
		c = putString(c, 1, t.Chat.Message)
		c = putString(c, 2, t.Chat.To)
		c = putString(c, 3, t.Chat.ToCallsign)
		b = putBytes(b, 6, c)
	} else if len(t.Detail) > 0 {
		b = putBytes(b, 7, t.Detail)
	}
	return b
}
