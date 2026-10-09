package media

import (
	"bytes"
	"encoding/binary"
)

const (
	tsPacketSize   = 188
	tsStreamH264   = 0x1b
	tsStreamKLV    = 0x15
	tsStreamPrivPS = 0x06
)

type TSDemuxer struct {
	OnVideo func(pts int64, annexB []byte)
	OnKLV   func(pts int64, data []byte)

	pmtPID int
	kinds  map[int]byte
	pes    map[int]*bytes.Buffer
	carry  []byte
}

func NewTSDemuxer() *TSDemuxer {
	return &TSDemuxer{pmtPID: -1, kinds: map[int]byte{}, pes: map[int]*bytes.Buffer{}}
}

func (d *TSDemuxer) Write(b []byte) {
	if len(d.carry) > 0 {
		b = append(d.carry, b...)
		d.carry = nil
	}
	for len(b) >= tsPacketSize {
		if b[0] != 0x47 {
			i := bytes.IndexByte(b[1:], 0x47)
			if i < 0 {
				return
			}
			b = b[i+1:]
			continue
		}
		d.packet(b[:tsPacketSize])
		b = b[tsPacketSize:]
	}
	if len(b) > 0 {
		d.carry = append([]byte(nil), b...)
	}
}

func (d *TSDemuxer) Flush() {
	for pid := range d.pes {
		d.finish(pid)
	}
}

func (d *TSDemuxer) packet(p []byte) {
	pusi := p[1]&0x40 != 0
	pid := int(p[1]&0x1f)<<8 | int(p[2])
	afc := (p[3] >> 4) & 3
	payload := p[4:]
	if afc == 2 {
		return
	}
	if afc == 3 {
		n := int(payload[0])
		if n+1 > len(payload) {
			return
		}
		payload = payload[n+1:]
	}
	switch {
	case pid == 0:
		d.pat(payload, pusi)
	case pid == d.pmtPID:
		d.pmt(payload, pusi)
	default:
		if _, ok := d.kinds[pid]; !ok {
			return
		}
		if pusi {
			d.finish(pid)
			d.pes[pid] = new(bytes.Buffer)
		}
		if buf := d.pes[pid]; buf != nil {
			buf.Write(payload)
			if b := buf.Bytes(); len(b) >= 6 {
				if n := int(b[4])<<8 | int(b[5]); n > 0 && len(b) >= 6+n {
					buf.Truncate(6 + n)
					d.finish(pid)
				}
			}
		}
	}
}

func section(payload []byte, pusi bool) []byte {
	if !pusi || len(payload) < 1 {
		return nil
	}
	ptr := int(payload[0])
	if 1+ptr >= len(payload) {
		return nil
	}
	s := payload[1+ptr:]
	if len(s) < 3 {
		return nil
	}
	n := int(s[1]&0x0f)<<8 | int(s[2])
	if 3+n > len(s) || n < 9 {
		return nil
	}
	return s[:3+n]
}

func (d *TSDemuxer) pat(payload []byte, pusi bool) {
	s := section(payload, pusi)
	if s == nil || s[0] != 0 {
		return
	}
	for i := 8; i+4 <= len(s)-4; i += 4 {
		prog := binary.BigEndian.Uint16(s[i:])
		if prog != 0 {
			d.pmtPID = int(s[i+2]&0x1f)<<8 | int(s[i+3])
			return
		}
	}
}

func (d *TSDemuxer) pmt(payload []byte, pusi bool) {
	s := section(payload, pusi)
	if s == nil || s[0] != 2 || len(s) < 12 {
		return
	}
	infoLen := int(s[10]&0x0f)<<8 | int(s[11])
	i := 12 + infoLen
	end := len(s) - 4
	for i+5 <= end {
		st := s[i]
		pid := int(s[i+1]&0x1f)<<8 | int(s[i+2])
		esLen := int(s[i+3]&0x0f)<<8 | int(s[i+4])
		desc := s[i+5 : min(i+5+esLen, end)]
		switch {
		case st == tsStreamH264:
			d.kinds[pid] = tsStreamH264
		case st == tsStreamKLV || (st == tsStreamPrivPS && klvDescriptor(desc)):
			d.kinds[pid] = tsStreamKLV
		}
		i += 5 + esLen
	}
}

func klvDescriptor(desc []byte) bool {
	for len(desc) >= 2 {
		tag, n := desc[0], int(desc[1])
		if 2+n > len(desc) {
			return false
		}
		if tag == 0x05 && n >= 4 && string(desc[2:6]) == "KLVA" {
			return true
		}
		desc = desc[2+n:]
	}
	return false
}

func (d *TSDemuxer) finish(pid int) {
	buf := d.pes[pid]
	delete(d.pes, pid)
	if buf == nil {
		return
	}
	b := buf.Bytes()
	if len(b) < 9 || b[0] != 0 || b[1] != 0 || b[2] != 1 {
		return
	}
	streamID := b[3]
	var pts int64 = -1
	data := b[6:]
	if streamID != 0xbc && streamID != 0xbe && streamID != 0xbf && streamID != 0xf0 && streamID != 0xf1 && streamID != 0xff && streamID != 0xf2 && streamID != 0xf8 {
		if len(b) < 9 {
			return
		}
		hl := int(b[8])
		if 9+hl > len(b) {
			return
		}
		if b[7]&0x80 != 0 && hl >= 5 {
			pts = parsePTS(b[9:14])
		}
		data = b[9+hl:]
	}
	switch d.kinds[pid] {
	case tsStreamH264:
		if d.OnVideo != nil && len(data) > 0 {
			d.OnVideo(pts, data)
		}
	case tsStreamKLV:
		if d.OnKLV != nil && len(data) > 0 {
			d.OnKLV(pts, data)
		}
	}
}

func parsePTS(b []byte) int64 {
	return int64(b[0]>>1&0x07)<<30 | int64(b[1])<<22 | int64(b[2]>>1)<<15 | int64(b[3])<<7 | int64(b[4]>>1)
}

func SplitAnnexB(b []byte) [][]byte {
	var out [][]byte
	start := -1
	i := 0
	for i+2 < len(b) {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			if start >= 0 {
				end := i
				if end > start && b[end-1] == 0 {
					end--
				}
				if end > start {
					out = append(out, b[start:end])
				}
			}
			i += 3
			start = i
			continue
		}
		i++
	}
	if start >= 0 && start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
