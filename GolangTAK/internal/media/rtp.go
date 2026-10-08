package media

import (
	"encoding/binary"
	"errors"
)

type RTPHeader struct {
	Marker      bool
	PayloadType uint8
	Seq         uint16
	Timestamp   uint32
	SSRC        uint32
}

var errShortRTP = errors.New("rtp packet too short")

func ParseRTP(pkt []byte) (RTPHeader, []byte, error) {
	var h RTPHeader
	if len(pkt) < 12 || pkt[0]>>6 != 2 {
		return h, nil, errShortRTP
	}
	cc := int(pkt[0] & 0x0f)
	h.Marker = pkt[1]&0x80 != 0
	h.PayloadType = pkt[1] & 0x7f
	h.Seq = binary.BigEndian.Uint16(pkt[2:])
	h.Timestamp = binary.BigEndian.Uint32(pkt[4:])
	h.SSRC = binary.BigEndian.Uint32(pkt[8:])
	off := 12 + cc*4
	if len(pkt) < off {
		return h, nil, errShortRTP
	}
	if pkt[0]&0x10 != 0 {
		if len(pkt) < off+4 {
			return h, nil, errShortRTP
		}
		off += 4 + int(binary.BigEndian.Uint16(pkt[off+2:]))*4
		if len(pkt) < off {
			return h, nil, errShortRTP
		}
	}
	end := len(pkt)
	if pkt[0]&0x20 != 0 {
		pad := int(pkt[end-1])
		if pad == 0 || end-pad < off {
			return h, nil, errShortRTP
		}
		end -= pad
	}
	return h, pkt[off:end], nil
}

func MarshalRTP(h RTPHeader, payload []byte) []byte {
	out := make([]byte, 12+len(payload))
	out[0] = 0x80
	out[1] = h.PayloadType & 0x7f
	if h.Marker {
		out[1] |= 0x80
	}
	binary.BigEndian.PutUint16(out[2:], h.Seq)
	binary.BigEndian.PutUint32(out[4:], h.Timestamp)
	binary.BigEndian.PutUint32(out[8:], h.SSRC)
	copy(out[12:], payload)
	return out
}
