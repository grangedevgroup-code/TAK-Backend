package server

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

type aisBits []byte

func aisArmor(payload string, fill int) aisBits {
	bits := make(aisBits, 0, len(payload)*6)
	for i := 0; i < len(payload); i++ {
		c := int(payload[i]) - 48
		if c > 40 {
			c -= 8
		}
		if c < 0 || c > 63 {
			return nil
		}
		for b := 5; b >= 0; b-- {
			bits = append(bits, byte(c>>b&1))
		}
	}
	if fill > 0 && fill <= len(bits) {
		bits = bits[:len(bits)-fill]
	}
	return bits
}

func (b aisBits) uint(start, n int) uint64 {
	if start+n > len(b) {
		return 0
	}
	var v uint64
	for i := start; i < start+n; i++ {
		v = v<<1 | uint64(b[i])
	}
	return v
}

func (b aisBits) int(start, n int) int64 {
	v := b.uint(start, n)
	if n > 0 && v&(1<<(n-1)) != 0 {
		return int64(v) - int64(1)<<n
	}
	return int64(v)
}

func (b aisBits) text(start, n int) string {
	if start >= len(b) {
		return ""
	}
	if start+n > len(b) {
		n = (len(b) - start) / 6 * 6
	}
	var sb strings.Builder
	for i := start; i+6 <= start+n; i += 6 {
		c := byte(b.uint(i, 6))
		if c < 32 {
			c += 64
		}
		sb.WriteByte(c)
	}
	return strings.TrimSpace(strings.TrimRight(sb.String(), "@ "))
}

func nmeaChecksumOK(line string) bool {
	star := strings.LastIndexByte(line, '*')
	if star < 1 || len(line) < star+3 {
		return false
	}
	want, err := strconv.ParseUint(line[star+1:star+3], 16, 8)
	if err != nil {
		return false
	}
	var sum byte
	for i := 1; i < star; i++ {
		sum ^= line[i]
	}
	return sum == byte(want)
}

type aisPart struct {
	parts []string
	at    time.Time
}

type aisDecoder struct {
	mu      sync.Mutex
	pending map[string]*aisPart
	vessels map[int64]map[string]any
	seen    map[int64]time.Time
}

func newAISDecoder() *aisDecoder {
	return &aisDecoder{pending: map[string]*aisPart{}, vessels: map[int64]map[string]any{}, seen: map[int64]time.Time{}}
}

func (d *aisDecoder) Line(line string) map[string]any {
	line = strings.TrimSpace(line)
	if i := strings.LastIndexByte(line, '\\'); i >= 0 {
		line = line[i+1:]
	}
	if len(line) < 10 || line[0] != '!' || !nmeaChecksumOK(line) {
		return nil
	}
	head := line[3:6]
	if head != "VDM" && head != "VDO" {
		return nil
	}
	f := strings.Split(line[:strings.LastIndexByte(line, '*')], ",")
	if len(f) < 7 {
		return nil
	}
	total, _ := strconv.Atoi(f[1])
	num, _ := strconv.Atoi(f[2])
	fill, _ := strconv.Atoi(f[6])
	if total < 1 || num < 1 || num > total || total > 9 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	payload := f[5]
	if total > 1 {
		key := f[3] + "/" + f[4]
		p := d.pending[key]
		if num == 1 || p == nil || len(p.parts) != num-1 || time.Since(p.at) > 10*time.Second {
			if num != 1 {
				delete(d.pending, key)
				return nil
			}
			p = &aisPart{at: time.Now()}
			d.pending[key] = p
		}
		p.parts = append(p.parts, payload)
		if num < total {
			return nil
		}
		delete(d.pending, key)
		payload = strings.Join(p.parts, "")
	}
	bits := aisArmor(payload, fill)
	if len(bits) < 38 {
		return nil
	}
	return d.decode(bits)
}

func (d *aisDecoder) vessel(mmsi int64) map[string]any {
	v := d.vessels[mmsi]
	if v == nil {
		if len(d.vessels) > 20000 {
			d.expire(0)
		}
		v = map[string]any{"MMSI": float64(mmsi)}
		d.vessels[mmsi] = v
	}
	return v
}

func (d *aisDecoder) expire(age time.Duration) {
	cut := time.Now().Add(-age)
	for k, t := range d.seen {
		if age == 0 || t.Before(cut) {
			delete(d.seen, k)
			delete(d.vessels, k)
		}
	}
}

func (d *aisDecoder) position(v map[string]any, mmsi int64, lon, lat int64, sog, cog, hdg uint64) map[string]any {
	la, lo := float64(lat)/600000, float64(lon)/600000
	if la < -90 || la > 90 || lo < -180 || lo > 180 {
		return nil
	}
	v["LATITUDE"], v["LONGITUDE"] = la, lo
	if sog < 1023 {
		v["SOG"] = float64(sog) / 10
	} else {
		delete(v, "SOG")
	}
	if cog < 3600 {
		v["COG"] = float64(cog) / 10
	} else {
		delete(v, "COG")
	}
	if hdg < 360 {
		v["HEADING"] = float64(hdg)
	} else {
		delete(v, "HEADING")
	}
	d.seen[mmsi] = time.Now()
	out := make(map[string]any, len(v))
	for k, x := range v {
		out[k] = x
	}
	return out
}

func (d *aisDecoder) decode(b aisBits) map[string]any {
	typ := b.uint(0, 6)
	mmsi := int64(b.uint(8, 30))
	if mmsi <= 0 {
		return nil
	}
	switch typ {
	case 1, 2, 3:
		if len(b) < 137 {
			return nil
		}
		return d.position(d.vessel(mmsi), mmsi, b.int(61, 28), b.int(89, 27), b.uint(50, 10), b.uint(116, 12), b.uint(128, 9))
	case 18:
		if len(b) < 133 {
			return nil
		}
		return d.position(d.vessel(mmsi), mmsi, b.int(57, 28), b.int(85, 27), b.uint(46, 10), b.uint(112, 12), b.uint(124, 9))
	case 19:
		if len(b) < 271 {
			return nil
		}
		v := d.vessel(mmsi)
		if n := b.text(143, 120); n != "" {
			v["NAME"] = n
		}
		v["TYPE"] = float64(b.uint(263, 8))
		return d.position(v, mmsi, b.int(57, 28), b.int(85, 27), b.uint(46, 10), b.uint(112, 12), b.uint(124, 9))
	case 5:
		if len(b) < 420 {
			return nil
		}
		v := d.vessel(mmsi)
		if imo := b.uint(40, 30); imo > 0 {
			v["IMO"] = float64(imo)
		}
		if c := b.text(70, 42); c != "" {
			v["CALLSIGN"] = c
		}
		if n := b.text(112, 120); n != "" {
			v["NAME"] = n
		}
		v["TYPE"] = float64(b.uint(232, 8))
		if dst := b.text(302, 120); dst != "" {
			v["DEST"] = dst
		}
	case 24:
		v := d.vessel(mmsi)
		switch b.uint(38, 2) {
		case 0:
			if n := b.text(40, 120); n != "" {
				v["NAME"] = n
			}
		case 1:
			if len(b) < 132 {
				return nil
			}
			v["TYPE"] = float64(b.uint(40, 8))
			if c := b.text(90, 42); c != "" {
				v["CALLSIGN"] = c
			}
		}
	}
	return nil
}
