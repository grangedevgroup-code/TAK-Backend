package quic

import (
	"errors"
)

var errFrame = errors.New("quic: malformed frame")

type ackRange struct{ lo, hi uint64 }

type frame struct {
	typ        uint64
	ackRanges  []ackRange
	offset     uint64
	data       []byte
	fin        bool
	streamID   uint64
	maxValue   uint64
	errorCode  uint64
	reason     string
	pathData   [8]byte
	seq        uint64
	retirePrio uint64
	connID     []byte
}

const (
	frPadding         = 0x00
	frPing            = 0x01
	frAck             = 0x02
	frAckECN          = 0x03
	frResetStream     = 0x04
	frStopSending     = 0x05
	frCrypto          = 0x06
	frNewToken        = 0x07
	frStream          = 0x08
	frMaxData         = 0x10
	frMaxStreamData   = 0x11
	frMaxStreamsBidi  = 0x12
	frMaxStreamsUni   = 0x13
	frDataBlocked     = 0x14
	frStreamBlocked   = 0x15
	frStreamsBlockedB = 0x16
	frStreamsBlockedU = 0x17
	frNewConnectionID = 0x18
	frRetireConnID    = 0x19
	frPathChallenge   = 0x1a
	frPathResponse    = 0x1b
	frConnClose       = 0x1c
	frConnCloseApp    = 0x1d
	frHandshakeDone   = 0x1e
)

type reader struct {
	b   []byte
	err bool
}

func (r *reader) varint() uint64 {
	v, n := readVarint(r.b)
	if n == 0 {
		r.err = true
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) bytes(n uint64) []byte {
	if uint64(len(r.b)) < n {
		r.err = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func parseFrames(b []byte) ([]frame, error) {
	r := &reader{b: b}
	var out []frame
	for len(r.b) > 0 && !r.err {
		t := r.varint()
		f := frame{typ: t}
		switch {
		case t == frPadding:
			for len(r.b) > 0 && r.b[0] == 0 {
				r.b = r.b[1:]
			}
			continue
		case t == frPing, t == frHandshakeDone:
		case t == frAck || t == frAckECN:
			largest := r.varint()
			r.varint()
			count := r.varint()
			first := r.varint()
			if first > largest {
				return nil, errFrame
			}
			f.ackRanges = append(f.ackRanges, ackRange{largest - first, largest})
			lo := largest - first
			for i := uint64(0); i < count && !r.err; i++ {
				gap := r.varint()
				length := r.varint()
				if lo < gap+2 {
					return nil, errFrame
				}
				hi := lo - gap - 2
				if hi < length {
					return nil, errFrame
				}
				f.ackRanges = append(f.ackRanges, ackRange{hi - length, hi})
				lo = hi - length
			}
			if t == frAckECN {
				r.varint()
				r.varint()
				r.varint()
			}
		case t == frResetStream:
			f.streamID = r.varint()
			f.errorCode = r.varint()
			f.maxValue = r.varint()
		case t == frStopSending:
			f.streamID = r.varint()
			f.errorCode = r.varint()
		case t == frCrypto:
			f.offset = r.varint()
			f.data = r.bytes(r.varint())
		case t == frNewToken:
			r.bytes(r.varint())
		case t >= 0x08 && t <= 0x0f:
			f.typ = frStream
			f.streamID = r.varint()
			if t&0x04 != 0 {
				f.offset = r.varint()
			}
			if t&0x02 != 0 {
				f.data = r.bytes(r.varint())
			} else {
				f.data = r.b
				r.b = nil
			}
			f.fin = t&0x01 != 0
		case t == frMaxData, t == frMaxStreamsBidi, t == frMaxStreamsUni, t == frDataBlocked, t == frStreamsBlockedB, t == frStreamsBlockedU:
			f.maxValue = r.varint()
		case t == frMaxStreamData, t == frStreamBlocked:
			f.streamID = r.varint()
			f.maxValue = r.varint()
		case t == frNewConnectionID:
			f.seq = r.varint()
			f.retirePrio = r.varint()
			if len(r.b) < 1 {
				return nil, errFrame
			}
			l := uint64(r.b[0])
			r.b = r.b[1:]
			f.connID = r.bytes(l)
			r.bytes(16)
		case t == frRetireConnID:
			f.seq = r.varint()
		case t == frPathChallenge, t == frPathResponse:
			copy(f.pathData[:], r.bytes(8))
		case t == frConnClose, t == frConnCloseApp:
			f.errorCode = r.varint()
			if t == frConnClose {
				r.varint()
			}
			f.reason = string(r.bytes(r.varint()))
		default:
			return nil, errFrame
		}
		if r.err {
			return nil, errFrame
		}
		out = append(out, f)
	}
	if r.err {
		return nil, errFrame
	}
	return out, nil
}

func ackEliciting(frames []frame) bool {
	for _, f := range frames {
		if f.typ != frAck && f.typ != frAckECN && f.typ != frPadding && f.typ != frConnClose && f.typ != frConnCloseApp {
			return true
		}
	}
	return false
}

func appendAck(b []byte, ranges []ackRange) []byte {
	if len(ranges) == 0 {
		return b
	}
	b = appendVarint(b, frAck)
	b = appendVarint(b, ranges[0].hi)
	b = appendVarint(b, 0)
	b = appendVarint(b, uint64(len(ranges)-1))
	b = appendVarint(b, ranges[0].hi-ranges[0].lo)
	lo := ranges[0].lo
	for _, r := range ranges[1:] {
		b = appendVarint(b, lo-r.hi-2)
		b = appendVarint(b, r.hi-r.lo)
		lo = r.lo
	}
	return b
}

func appendCrypto(b []byte, offset uint64, data []byte) []byte {
	b = appendVarint(b, frCrypto)
	b = appendVarint(b, offset)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendStream(b []byte, id, offset uint64, data []byte, fin bool) []byte {
	t := uint64(0x08 | 0x02)
	if offset > 0 {
		t |= 0x04
	}
	if fin {
		t |= 0x01
	}
	b = appendVarint(b, t)
	b = appendVarint(b, id)
	if offset > 0 {
		b = appendVarint(b, offset)
	}
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func streamFrameOverhead(id, offset uint64, n int) int {
	o := 1 + varintLen(id) + varintLen(uint64(n))
	if offset > 0 {
		o += varintLen(offset)
	}
	return o
}

func appendConnClose(b []byte, code uint64, reason string) []byte {
	b = appendVarint(b, frConnClose)
	b = appendVarint(b, code)
	b = appendVarint(b, 0)
	b = appendVarint(b, uint64(len(reason)))
	return append(b, reason...)
}

type transportParams struct {
	origDCID         []byte
	initialSCID      []byte
	maxIdleTimeoutMs uint64
	maxUDPPayload    uint64
	initialMaxData   uint64
	maxStreamDataBL  uint64
	maxStreamDataBR  uint64
	maxStreamDataUni uint64
	maxStreamsBidi   uint64
	maxStreamsUni    uint64
	activeCIDLimit   uint64
	disableMigration bool
	statelessReset   []byte
	ackDelayExponent uint64
	maxAckDelay      uint64
}

func appendParam(b []byte, id uint64, v []byte) []byte {
	b = appendVarint(b, id)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func (p transportParams) encode() []byte {
	var b []byte
	iv := func(id, v uint64) {
		b = appendParam(b, id, appendVarint(nil, v))
	}
	if p.origDCID != nil {
		b = appendParam(b, 0x00, p.origDCID)
	}
	iv(0x01, p.maxIdleTimeoutMs)
	if p.statelessReset != nil {
		b = appendParam(b, 0x02, p.statelessReset)
	}
	if p.maxUDPPayload != 0 {
		iv(0x03, p.maxUDPPayload)
	}
	iv(0x04, p.initialMaxData)
	iv(0x05, p.maxStreamDataBL)
	iv(0x06, p.maxStreamDataBR)
	iv(0x07, p.maxStreamDataUni)
	iv(0x08, p.maxStreamsBidi)
	iv(0x09, p.maxStreamsUni)
	if p.disableMigration {
		b = appendParam(b, 0x0c, nil)
	}
	if p.activeCIDLimit != 0 {
		iv(0x0e, p.activeCIDLimit)
	}
	b = appendParam(b, 0x0f, p.initialSCID)
	return b
}

func decodeTransportParams(b []byte) (transportParams, error) {
	p := transportParams{maxUDPPayload: 65527, ackDelayExponent: 3, maxAckDelay: 25, activeCIDLimit: 2}
	r := &reader{b: b}
	for len(r.b) > 0 {
		id := r.varint()
		v := r.bytes(r.varint())
		if r.err {
			return p, errFrame
		}
		num := func() uint64 { x, _ := readVarint(v); return x }
		switch id {
		case 0x00:
			p.origDCID = v
		case 0x01:
			p.maxIdleTimeoutMs = num()
		case 0x02:
			p.statelessReset = v
		case 0x03:
			p.maxUDPPayload = num()
		case 0x04:
			p.initialMaxData = num()
		case 0x05:
			p.maxStreamDataBL = num()
		case 0x06:
			p.maxStreamDataBR = num()
		case 0x07:
			p.maxStreamDataUni = num()
		case 0x08:
			p.maxStreamsBidi = num()
		case 0x09:
			p.maxStreamsUni = num()
		case 0x0a:
			p.ackDelayExponent = num()
		case 0x0b:
			p.maxAckDelay = num()
		case 0x0c:
			p.disableMigration = true
		case 0x0e:
			p.activeCIDLimit = num()
		case 0x0f:
			p.initialSCID = v
		}
	}
	return p, nil
}
