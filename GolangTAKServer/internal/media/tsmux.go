package media

const (
	tsPMTPID   = 0x1000
	tsVideoPID = 0x100
	tsKLVPID   = 0x101
)

type TSMuxer struct {
	cc map[int]byte
}

func NewTSMuxer() *TSMuxer { return &TSMuxer{cc: map[int]byte{}} }

func crc32MPEG(b []byte) uint32 {
	crc := uint32(0xffffffff)
	for _, x := range b {
		crc ^= uint32(x) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04c11db7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func (m *TSMuxer) packets(pid int, payload []byte, pusi bool) []byte {
	var out []byte
	first := true
	for len(payload) > 0 || first {
		pkt := make([]byte, tsPacketSize)
		pkt[0] = 0x47
		pkt[1] = byte(pid>>8) & 0x1f
		if first && pusi {
			pkt[1] |= 0x40
		}
		pkt[2] = byte(pid)
		cc := m.cc[pid]
		m.cc[pid] = (cc + 1) & 0x0f
		room := tsPacketSize - 4
		if len(payload) >= room {
			pkt[3] = 0x10 | cc
			copy(pkt[4:], payload[:room])
			payload = payload[room:]
		} else {
			pad := room - len(payload)
			pkt[3] = 0x30 | cc
			pkt[4] = byte(pad - 1)
			if pad > 1 {
				pkt[5] = 0
				for i := 6; i < 4+pad; i++ {
					pkt[i] = 0xff
				}
			}
			copy(pkt[4+pad:], payload)
			payload = nil
		}
		out = append(out, pkt...)
		first = false
	}
	return out
}

func (m *TSMuxer) psi(pid int, table []byte) []byte {
	crc := crc32MPEG(table)
	sec := append(append([]byte{0}, table...), byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc))
	return m.packets(pid, sec, true)
}

func (m *TSMuxer) Tables() []byte {
	pat := []byte{0x00, 0xb0, 13, 0x00, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x01, 0xe0 | byte(tsPMTPID>>8), byte(tsPMTPID & 0xff)}
	klvDesc := []byte{0x05, 0x04, 'K', 'L', 'V', 'A'}
	streams := []byte{tsStreamH264, 0xe0 | byte(tsVideoPID>>8), byte(tsVideoPID & 0xff), 0xf0, 0x00}
	streams = append(streams, tsStreamPrivPS, 0xe0|byte(tsKLVPID>>8), byte(tsKLVPID&0xff), 0xf0, byte(len(klvDesc)))
	streams = append(streams, klvDesc...)
	body := append([]byte{0x00, 0x01, 0xc1, 0x00, 0x00, 0xe0 | byte(tsVideoPID>>8), byte(tsVideoPID & 0xff), 0xf0, 0x00}, streams...)
	n := len(body) + 4
	pmt := append([]byte{0x02, 0xb0 | byte(n>>8), byte(n)}, body...)
	return append(m.psi(0, pat), m.psi(tsPMTPID, pmt)...)
}

func ptsBytes(pts int64, marker byte) []byte {
	return []byte{marker<<4 | byte(pts>>29)&0x0e | 1, byte(pts >> 22), byte(pts>>14)&0xfe | 1, byte(pts >> 7), byte(pts<<1) | 1}
}

func (m *TSMuxer) pes(pid int, streamID byte, pts int64, data []byte) []byte {
	hdr := []byte{0, 0, 1, streamID, 0, 0, 0x80, 0x80, 5}
	hdr = append(hdr, ptsBytes(pts, 2)...)
	if streamID != 0xe0 {
		n := len(hdr) - 6 + len(data)
		hdr[4], hdr[5] = byte(n>>8), byte(n)
	}
	return m.packets(pid, append(hdr, data...), true)
}

func (m *TSMuxer) Video(pts int64, nals [][]byte) []byte {
	var annexB []byte
	annexB = append(annexB, 0, 0, 0, 1, 9, 0xf0)
	for _, n := range nals {
		annexB = append(annexB, 0, 0, 0, 1)
		annexB = append(annexB, n...)
	}
	return m.pes(tsVideoPID, 0xe0, pts, annexB)
}

func (m *TSMuxer) KLV(pts int64, data []byte) []byte {
	return m.pes(tsKLVPID, 0xbd, pts, data)
}
