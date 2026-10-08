package media

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	nalIDR  = 5
	nalSPS  = 7
	nalPPS  = 8
	nalAUD  = 9
	nalSTAP = 24
	nalFUA  = 28
	maxAU   = 8 << 20
)

type AccessUnit struct {
	Timestamp uint32
	NALUs     [][]byte
	Key       bool
}

type H264Depacketizer struct {
	OnAU func(AccessUnit)
	SPS  []byte
	PPS  []byte

	fu      []byte
	fuOK    bool
	nalus   [][]byte
	size    int
	ts      uint32
	have    bool
	lastSeq uint16
	seqOK   bool
}

func (d *H264Depacketizer) flush() {
	if len(d.nalus) == 0 {
		d.have = false
		return
	}
	au := AccessUnit{Timestamp: d.ts}
	for _, n := range d.nalus {
		switch n[0] & 0x1f {
		case nalSPS:
			d.SPS = n
		case nalPPS:
			d.PPS = n
		case nalIDR:
			au.Key = true
		case nalAUD:
			continue
		}
		au.NALUs = append(au.NALUs, n)
	}
	d.nalus, d.size, d.have = nil, 0, false
	if len(au.NALUs) > 0 && d.OnAU != nil {
		d.OnAU(au)
	}
}

func (d *H264Depacketizer) add(n []byte) {
	if len(n) == 0 || d.size+len(n) > maxAU {
		return
	}
	d.nalus = append(d.nalus, n)
	d.size += len(n)
}

func (d *H264Depacketizer) Push(h RTPHeader, payload []byte) {
	if d.seqOK && h.Seq != d.lastSeq+1 {
		d.fu, d.fuOK = nil, false
	}
	d.lastSeq, d.seqOK = h.Seq, true
	if d.have && h.Timestamp != d.ts {
		d.flush()
	}
	if len(payload) == 0 {
		return
	}
	d.ts, d.have = h.Timestamp, true
	switch t := payload[0] & 0x1f; {
	case t >= 1 && t <= 23:
		d.add(append([]byte(nil), payload...))
	case t == nalSTAP:
		p := payload[1:]
		for len(p) >= 2 {
			n := int(binary.BigEndian.Uint16(p))
			p = p[2:]
			if n > len(p) {
				break
			}
			d.add(append([]byte(nil), p[:n]...))
			p = p[n:]
		}
	case t == nalFUA:
		if len(payload) < 2 {
			return
		}
		ind, hdr := payload[0], payload[1]
		if hdr&0x80 != 0 {
			d.fu = append([]byte{ind&0xe0 | hdr&0x1f}, payload[2:]...)
			d.fuOK = true
		} else if d.fuOK {
			if len(d.fu)+len(payload) > maxAU {
				d.fu, d.fuOK = nil, false
				return
			}
			d.fu = append(d.fu, payload[2:]...)
		}
		if hdr&0x40 != 0 && d.fuOK {
			d.add(d.fu)
			d.fu, d.fuOK = nil, false
		}
	}
	if h.Marker {
		d.flush()
	}
}

type SPSInfo struct {
	Profile int
	Compat  int
	Level   int
	Width   int
	Height  int
}

func (s SPSInfo) Codec() string {
	return fmt.Sprintf("avc1.%02X%02X%02X", s.Profile, s.Compat, s.Level)
}

type bitReader struct {
	b   []byte
	pos int
}

func (r *bitReader) bit() (uint, error) {
	if r.pos >= len(r.b)*8 {
		return 0, errors.New("sps too short")
	}
	v := uint(r.b[r.pos/8]>>(7-r.pos%8)) & 1
	r.pos++
	return v, nil
}

func (r *bitReader) bits(n int) (uint, error) {
	var v uint
	for i := 0; i < n; i++ {
		b, err := r.bit()
		if err != nil {
			return 0, err
		}
		v = v<<1 | b
	}
	return v, nil
}

func (r *bitReader) ue() (uint, error) {
	zeros := 0
	for {
		b, err := r.bit()
		if err != nil {
			return 0, err
		}
		if b == 1 {
			break
		}
		zeros++
		if zeros > 31 {
			return 0, errors.New("bad exp-golomb value")
		}
	}
	v, err := r.bits(zeros)
	return (1 << zeros) - 1 + v, err
}

func (r *bitReader) se() (int, error) {
	v, err := r.ue()
	if v%2 == 1 {
		return int(v+1) / 2, err
	}
	return -int(v / 2), err
}

func unescapeRBSP(b []byte) []byte {
	out := make([]byte, 0, len(b))
	zeros := 0
	for _, c := range b {
		if zeros >= 2 && c == 3 {
			zeros = 0
			continue
		}
		if c == 0 {
			zeros++
		} else {
			zeros = 0
		}
		out = append(out, c)
	}
	return out
}

func ParseSPS(sps []byte) (SPSInfo, error) {
	var info SPSInfo
	if len(sps) < 4 {
		return info, errors.New("sps too short")
	}
	info.Profile, info.Compat, info.Level = int(sps[1]), int(sps[2]), int(sps[3])
	r := &bitReader{b: unescapeRBSP(sps[4:])}
	fail := func(err error) (SPSInfo, error) { return info, err }
	if _, err := r.ue(); err != nil {
		return fail(err)
	}
	chroma := uint(1)
	switch info.Profile {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		var err error
		if chroma, err = r.ue(); err != nil {
			return fail(err)
		}
		if chroma == 3 {
			r.bit()
		}
		r.ue()
		r.ue()
		r.bit()
		present, err := r.bit()
		if err != nil {
			return fail(err)
		}
		if present == 1 {
			n := 8
			if chroma == 3 {
				n = 12
			}
			for i := 0; i < n; i++ {
				f, err := r.bit()
				if err != nil {
					return fail(err)
				}
				if f == 1 {
					size := 16
					if i >= 6 {
						size = 64
					}
					last, next := 8, 8
					for j := 0; j < size; j++ {
						if next != 0 {
							d, err := r.se()
							if err != nil {
								return fail(err)
							}
							next = (last + d + 256) % 256
						}
						if next != 0 {
							last = next
						}
					}
				}
			}
		}
	}
	if _, err := r.ue(); err != nil {
		return fail(err)
	}
	poc, err := r.ue()
	if err != nil {
		return fail(err)
	}
	switch poc {
	case 0:
		r.ue()
	case 1:
		r.bit()
		r.se()
		r.se()
		n, err := r.ue()
		if err != nil || n > 255 {
			return fail(errors.New("bad sps"))
		}
		for i := uint(0); i < n; i++ {
			r.se()
		}
	}
	r.ue()
	r.bit()
	wmbs, err := r.ue()
	if err != nil {
		return fail(err)
	}
	hmbs, err := r.ue()
	if err != nil {
		return fail(err)
	}
	frameOnly, err := r.bit()
	if err != nil {
		return fail(err)
	}
	if frameOnly == 0 {
		r.bit()
	}
	r.bit()
	width := int(wmbs+1) * 16
	height := int(2-frameOnly) * int(hmbs+1) * 16
	crop, err := r.bit()
	if err != nil {
		return fail(err)
	}
	if crop == 1 {
		l, _ := r.ue()
		rr, _ := r.ue()
		t, _ := r.ue()
		b, err := r.ue()
		if err != nil {
			return fail(err)
		}
		cx, cy := 2, 2*int(2-frameOnly)
		if chroma == 0 {
			cx, cy = 1, int(2-frameOnly)
		} else if chroma == 3 {
			cx = 1
		} else if chroma == 2 {
			cy = int(2 - frameOnly)
		}
		width -= int(l+rr) * cx
		height -= int(t+b) * cy
	}
	if width <= 0 || height <= 0 || width > 16384 || height > 16384 {
		return fail(errors.New("bad picture size"))
	}
	info.Width, info.Height = width, height
	return info, nil
}

func PacketizeH264(au AccessUnit, pt uint8, ssrc uint32, seq *uint16, mtu int) [][]byte {
	var out [][]byte
	for i, n := range au.NALUs {
		last := i == len(au.NALUs)-1
		if len(n) <= mtu {
			out = append(out, MarshalRTP(RTPHeader{Marker: last, PayloadType: pt, Seq: *seq, Timestamp: au.Timestamp, SSRC: ssrc}, n))
			*seq++
			continue
		}
		ind := n[0]&0xe0 | nalFUA
		typ := n[0] & 0x1f
		data := n[1:]
		first := true
		for len(data) > 0 {
			chunk := min(len(data), mtu-2)
			hdr := typ
			if first {
				hdr |= 0x80
			}
			end := chunk == len(data)
			if end {
				hdr |= 0x40
			}
			out = append(out, MarshalRTP(RTPHeader{Marker: last && end, PayloadType: pt, Seq: *seq, Timestamp: au.Timestamp, SSRC: ssrc}, append([]byte{ind, hdr}, data[:chunk]...)))
			*seq++
			data = data[chunk:]
			first = false
		}
	}
	return out
}
