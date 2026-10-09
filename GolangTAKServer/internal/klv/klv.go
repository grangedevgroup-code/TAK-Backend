package klv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"
)

var UASKey = []byte{0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00}

var ErrChecksum = errors.New("klv: checksum mismatch")

type Corner struct{ Lat, Lon float64 }

type UAS struct {
	Time              time.Time
	Mission           string
	TailNumber        string
	Designation       string
	SensorName        string
	Heading           float64
	Pitch             float64
	Roll              float64
	SensorLat         float64
	SensorLon         float64
	SensorAlt         float64
	SensorHAE         float64
	HFOV              float64
	VFOV              float64
	SensorRelAzimuth  float64
	SensorRelElev     float64
	SensorRelRoll     float64
	SlantRange        float64
	FrameLat          float64
	FrameLon          float64
	FrameElev         float64
	GroundSpeed       float64
	Corners           []Corner
	HasSensor         bool
	HasAlt            bool
	HasHAE            bool
	HasFrame          bool
	HasHeading        bool
	HasFOV            bool
	HasRelAz          bool
	HasRelElev        bool
	HasSlant          bool
	HasGroundSpeed    bool
	HasFrameElevation bool
}

func (u *UAS) Name() string {
	for _, v := range []string{u.Designation, u.TailNumber, u.Mission} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func (u *UAS) SensorAzimuth() float64 {
	return math.Mod(u.Heading+u.SensorRelAzimuth+720, 360)
}

func ber(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("klv: short length")
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 4 || 1+n > len(b) {
		return 0, 0, errors.New("klv: bad length")
	}
	v := 0
	for _, x := range b[1 : 1+n] {
		v = v<<8 | int(x)
	}
	return v, 1 + n, nil
}

func berOID(b []byte) (int, int, error) {
	v := 0
	for i, x := range b {
		if i >= 4 {
			break
		}
		v = v<<7 | int(x&0x7f)
		if x&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("klv: bad tag")
}

func FindAll(data []byte) [][]byte {
	var out [][]byte
	for {
		i := bytes.Index(data, UASKey)
		if i < 0 {
			return out
		}
		data = data[i:]
		n, l, err := ber(data[16:])
		if err != nil || 16+l+n > len(data) {
			return out
		}
		out = append(out, data[:16+l+n])
		data = data[16+l+n:]
	}
}

func checksum(b []byte) uint16 {
	var s uint16
	for i, x := range b {
		s += uint16(x) << (8 * uint((i+1)%2))
	}
	return s
}

func u16(v []byte) uint64 {
	var x uint64
	for _, b := range v {
		x = x<<8 | uint64(b)
	}
	return x
}

func s16(v []byte) int64 {
	if len(v) == 0 {
		return 0
	}
	x := int64(int8(v[0]))
	for _, b := range v[1:] {
		x = x<<8 | int64(b)
	}
	return x
}

func scaleU(v []byte, lo, hi float64) float64 {
	max := math.Pow(2, float64(8*len(v))) - 1
	return lo + float64(u16(v))*(hi-lo)/max
}

func scaleS(v []byte, span float64) (float64, bool) {
	if len(v) == 0 {
		return 0, false
	}
	bits := 8 * len(v)
	raw := s16(v)
	if raw == -(int64(1) << (bits - 1)) {
		return 0, false
	}
	max := math.Pow(2, float64(bits)) - 2
	return float64(raw) * span / max, true
}

func Parse(pkt []byte) (*UAS, error) {
	if len(pkt) < 17 || !bytes.Equal(pkt[:16], UASKey) {
		return nil, errors.New("klv: not a UAS datalink local set")
	}
	n, l, err := ber(pkt[16:])
	if err != nil {
		return nil, err
	}
	body := pkt[16+l:]
	if n > len(body) {
		return nil, errors.New("klv: truncated packet")
	}
	body = body[:n]
	u := &UAS{}
	var corners [8]float64
	var cornerOffsets [8]float64
	haveCorner, haveOffset := 0, 0
	pos := 0
	for pos < len(body) {
		tag, tl, err := berOID(body[pos:])
		if err != nil {
			return nil, err
		}
		vl, ll, err := ber(body[pos+tl:])
		if err != nil {
			return nil, err
		}
		start := pos + tl + ll
		if start+vl > len(body) {
			return nil, errors.New("klv: value past end")
		}
		v := body[start : start+vl]
		if tag == 1 && vl == 2 {
			end := 16 + l + start
			if got, want := checksum(pkt[:end]), binary.BigEndian.Uint16(v); got != want {
				return nil, ErrChecksum
			}
		}
		u.set(tag, v, &corners, &cornerOffsets, &haveCorner, &haveOffset)
		pos = start + vl
	}
	if haveCorner == 0xff {
		for i := 0; i < 4; i++ {
			u.Corners = append(u.Corners, Corner{corners[2*i], corners[2*i+1]})
		}
	} else if haveOffset == 0xff && u.HasFrame {
		for i := 0; i < 4; i++ {
			u.Corners = append(u.Corners, Corner{u.FrameLat + cornerOffsets[2*i], u.FrameLon + cornerOffsets[2*i+1]})
		}
	}
	return u, nil
}

func (u *UAS) set(tag int, v []byte, corners, offsets *[8]float64, haveCorner, haveOffset *int) {
	switch tag {
	case 2:
		if len(v) == 8 {
			us := binary.BigEndian.Uint64(v)
			u.Time = time.UnixMicro(int64(us)).UTC()
		}
	case 3:
		u.Mission = string(v)
	case 4:
		u.TailNumber = string(v)
	case 5:
		if len(v) == 2 {
			u.Heading, u.HasHeading = scaleU(v, 0, 360), true
		}
	case 6:
		u.Pitch, _ = scaleS(v, 40)
	case 7:
		u.Roll, _ = scaleS(v, 100)
	case 10:
		u.Designation = string(v)
	case 11:
		u.SensorName = string(v)
	case 13:
		if x, ok := scaleS(v, 180); ok && len(v) == 4 {
			u.SensorLat = x
			u.HasSensor = true
		}
	case 14:
		if x, ok := scaleS(v, 360); ok && len(v) == 4 {
			u.SensorLon = x
		} else {
			u.HasSensor = false
		}
	case 15:
		if len(v) == 2 {
			u.SensorAlt, u.HasAlt = scaleU(v, -900, 19000), true
		}
	case 16:
		if len(v) == 2 {
			u.HFOV, u.HasFOV = scaleU(v, 0, 180), true
		}
	case 17:
		if len(v) == 2 {
			u.VFOV = scaleU(v, 0, 180)
		}
	case 18:
		if len(v) == 4 {
			u.SensorRelAzimuth, u.HasRelAz = scaleU(v, 0, 360), true
		}
	case 19:
		if x, ok := scaleS(v, 360); ok && len(v) == 4 {
			u.SensorRelElev, u.HasRelElev = x, true
		}
	case 20:
		if len(v) == 4 {
			u.SensorRelRoll = scaleU(v, 0, 360)
		}
	case 21:
		if len(v) == 4 {
			u.SlantRange, u.HasSlant = scaleU(v, 0, 5000000), true
		}
	case 23:
		if x, ok := scaleS(v, 180); ok && len(v) == 4 {
			u.FrameLat = x
			u.HasFrame = true
		}
	case 24:
		if x, ok := scaleS(v, 360); ok && len(v) == 4 {
			u.FrameLon = x
		} else {
			u.HasFrame = false
		}
	case 25:
		if len(v) == 2 {
			u.FrameElev, u.HasFrameElevation = scaleU(v, -900, 19000), true
		}
	case 26, 27, 28, 29, 30, 31, 32, 33:
		if x, ok := scaleS(v, 0.15); ok && len(v) == 2 {
			offsets[tag-26] = x
			*haveOffset |= 1 << (tag - 26)
		}
	case 56:
		if len(v) == 1 {
			u.GroundSpeed, u.HasGroundSpeed = float64(v[0]), true
		}
	case 75:
		if len(v) == 2 {
			u.SensorHAE, u.HasHAE = scaleU(v, -900, 19000), true
		}
	case 82, 83, 84, 85, 86, 87, 88, 89:
		i := tag - 82
		span := 180.0
		if i%2 == 1 {
			span = 360
		}
		if x, ok := scaleS(v, span); ok && len(v) == 4 {
			corners[i] = x
			*haveCorner |= 1 << i
		}
	}
}

func appendBER(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n < 0x100:
		return append(b, 0x81, byte(n))
	default:
		return append(b, 0x82, byte(n>>8), byte(n))
	}
}

type Item struct {
	Tag   int
	Value []byte
}

func Encode(items []Item) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, byte(it.Tag))
		body = appendBER(body, len(it.Value))
		body = append(body, it.Value...)
	}
	total := len(body) + 4
	pkt := append([]byte(nil), UASKey...)
	pkt = appendBER(pkt, total)
	pkt = append(pkt, body...)
	pkt = append(pkt, 1, 2)
	cs := checksum(pkt)
	return append(pkt, byte(cs>>8), byte(cs))
}

func EncodeU(x, lo, hi float64, size int) []byte {
	max := math.Pow(2, float64(8*size)) - 1
	v := uint64(math.Round((x - lo) * max / (hi - lo)))
	out := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}

func EncodeS(x, span float64, size int) []byte {
	max := math.Pow(2, float64(8*size)) - 2
	v := int64(math.Round(x * max / span))
	out := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}
