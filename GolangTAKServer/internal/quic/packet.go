package quic

import (
	"encoding/binary"
	"errors"
)

const (
	version1    = 0x00000001
	cidLen      = 8
	minInitial  = 1200
	maxDatagram = 1200
)

type packetType int

const (
	ptInitial packetType = iota
	ptZeroRTT
	ptHandshake
	ptRetry
	ptShort
)

var errShort = errors.New("quic: packet too short")

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
	}
}

func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	}
	return 8
}

func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

type header struct {
	typ      packetType
	version  uint32
	dcid     []byte
	scid     []byte
	token    []byte
	pnOffset int
	end      int
}

func parseHeader(b []byte, shortCIDLen int) (header, error) {
	var h header
	if len(b) < 1 {
		return h, errShort
	}
	if b[0]&0x80 == 0 {
		h.typ = ptShort
		if len(b) < 1+shortCIDLen {
			return h, errShort
		}
		h.dcid = b[1 : 1+shortCIDLen]
		h.pnOffset = 1 + shortCIDLen
		h.end = len(b)
		return h, nil
	}
	if len(b) < 7 {
		return h, errShort
	}
	h.version = binary.BigEndian.Uint32(b[1:5])
	p := 5
	dl := int(b[p])
	p++
	if len(b) < p+dl+1 || dl > 20 {
		return h, errShort
	}
	h.dcid = b[p : p+dl]
	p += dl
	sl := int(b[p])
	p++
	if len(b) < p+sl || sl > 20 {
		return h, errShort
	}
	h.scid = b[p : p+sl]
	p += sl
	if h.version == 0 {
		h.end = len(b)
		return h, nil
	}
	h.typ = packetType((b[0] >> 4) & 0x3)
	if h.typ == ptRetry {
		h.end = len(b)
		return h, nil
	}
	if h.typ == ptInitial {
		tl, n := readVarint(b[p:])
		if n == 0 || len(b) < p+n+int(tl) {
			return h, errShort
		}
		p += n
		h.token = b[p : p+int(tl)]
		p += int(tl)
	}
	length, n := readVarint(b[p:])
	if n == 0 {
		return h, errShort
	}
	p += n
	if len(b) < p+int(length) {
		return h, errShort
	}
	h.pnOffset = p
	h.end = p + int(length)
	return h, nil
}

func decodePN(largest int64, truncated uint64, pnLen int) uint64 {
	expected := largest + 1
	win := int64(1) << (pnLen * 8)
	hwin := win / 2
	mask := win - 1
	candidate := (expected &^ mask) | int64(truncated)
	if candidate <= expected-hwin && candidate < (1<<62)-win {
		return uint64(candidate + win)
	}
	if candidate > expected+hwin && candidate >= win {
		return uint64(candidate - win)
	}
	return uint64(candidate)
}

func unprotect(k *keys, pkt []byte, h header, largest int64) (pn uint64, payload []byte, keyPhase bool, err error) {
	if h.pnOffset+20 > h.end {
		return 0, nil, false, errShort
	}
	m := k.mask(pkt[h.pnOffset+4 : h.pnOffset+20])
	if h.typ == ptShort {
		pkt[0] ^= m[0] & 0x1f
		keyPhase = pkt[0]&0x04 != 0
	} else {
		pkt[0] ^= m[0] & 0x0f
	}
	pnLen := int(pkt[0]&0x3) + 1
	var trunc uint64
	pnb := pkt[h.pnOffset : h.pnOffset+pnLen]
	for i, mb := range m[1 : 1+pnLen] {
		pnb[i] ^= mb
		trunc = trunc<<8 | uint64(pnb[i])
	}
	pn = decodePN(largest, trunc, pnLen)
	hdr := pkt[:h.pnOffset+pnLen]
	payload, err = k.aead.Open(nil, k.nonce(pn), pkt[h.pnOffset+pnLen:h.end], hdr)
	return pn, payload, keyPhase, err
}

func unprotectTry(k *keys, pkt []byte, h header, largest int64) (uint64, []byte, bool, error) {
	cp := append([]byte(nil), pkt[:h.end]...)
	pn, payload, kp, err := unprotect(k, cp, h, largest)
	return pn, payload, kp, err
}

func longHeader(t packetType, dcid, scid, token []byte, pn uint64, payloadLen int) []byte {
	b := []byte{0xc0 | byte(t)<<4 | 0x03}
	b = binary.BigEndian.AppendUint32(b, version1)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	if t == ptInitial {
		b = appendVarint(b, uint64(len(token)))
		b = append(b, token...)
	}
	l := 4 + payloadLen + 16
	b = append(b, byte(0x40|(l>>8)), byte(l))
	return binary.BigEndian.AppendUint32(b, uint32(pn))
}

func shortHeader(dcid []byte, pn uint64, keyPhase bool) []byte {
	first := byte(0x40 | 0x03)
	if keyPhase {
		first |= 0x04
	}
	b := append([]byte{first}, dcid...)
	return binary.BigEndian.AppendUint32(b, uint32(pn))
}

func seal(k *keys, hdr []byte, pn uint64, payload []byte, short bool) []byte {
	pnOffset := len(hdr) - 4
	out := k.aead.Seal(append([]byte(nil), hdr...), k.nonce(pn), payload, hdr)
	m := k.mask(out[pnOffset+4 : pnOffset+20])
	if short {
		out[0] ^= m[0] & 0x1f
	} else {
		out[0] ^= m[0] & 0x0f
	}
	for i := 0; i < 4; i++ {
		out[pnOffset+i] ^= m[1+i]
	}
	return out
}

func versionNegotiation(dcid, scid []byte) []byte {
	b := []byte{0x80 | 0x40}
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	return binary.BigEndian.AppendUint32(b, version1)
}
