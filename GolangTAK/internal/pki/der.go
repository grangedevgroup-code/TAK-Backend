package pki

import (
	"bytes"
	"errors"
	"math/big"
	"sort"
	"unicode/utf16"
)

var errDER = errors.New("pki: malformed DER")

func appendLength(b []byte, n int) []byte {
	if n < 0x80 {
		return append(b, byte(n))
	}
	var tmp [8]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n)
		n >>= 8
	}
	b = append(b, 0x80|byte(len(tmp)-i))
	return append(b, tmp[i:]...)
}

func tlv(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n+6)
	b = append(b, tag)
	b = appendLength(b, n)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func seq(parts ...[]byte) []byte { return tlv(0x30, parts...) }

func set(parts ...[]byte) []byte {
	sorted := append([][]byte(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	return tlv(0x31, sorted...)
}

func octet(b []byte) []byte { return tlv(0x04, b) }

func null() []byte { return []byte{0x05, 0x00} }

func explicit(tag int, inner []byte) []byte { return tlv(0xa0|byte(tag), inner) }

func implicitPrimitive(tag int, content []byte) []byte { return tlv(0x80|byte(tag), content) }

func integer(v int64) []byte {
	b := new(big.Int).SetInt64(v).Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(0x02, b)
}

func oid(ids ...int) []byte {
	if len(ids) < 2 {
		panic("pki: short oid")
	}
	var b []byte
	b = appendBase128(b, ids[0]*40+ids[1])
	for _, id := range ids[2:] {
		b = appendBase128(b, id)
	}
	return tlv(0x06, b)
}

func appendBase128(b []byte, n int) []byte {
	if n == 0 {
		return append(b, 0)
	}
	var tmp [10]byte
	i := len(tmp)
	last := true
	for n > 0 {
		i--
		c := byte(n & 0x7f)
		if !last {
			c |= 0x80
		}
		tmp[i] = c
		last = false
		n >>= 7
	}
	return append(b, tmp[i:]...)
}

func bmpString(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c>>8), byte(c))
	}
	return tlv(0x1e, b)
}

func bmpPassword(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2+2)
	for _, c := range u {
		b = append(b, byte(c>>8), byte(c))
	}
	return append(b, 0, 0)
}

type elem struct {
	tag     byte
	content []byte
	full    []byte
}

func readElem(b []byte) (elem, []byte, error) {
	if len(b) < 2 {
		return elem{}, nil, errDER
	}
	tag := b[0]
	if tag&0x1f == 0x1f {
		return elem{}, nil, errDER
	}
	l := int(b[1])
	off := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return elem{}, nil, errDER
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		off = 2 + n
	}
	if l < 0 || len(b)-off < l {
		return elem{}, nil, errDER
	}
	return elem{tag: tag, content: b[off : off+l], full: b[:off+l]}, b[off+l:], nil
}

func children(b []byte) ([]elem, error) {
	var out []elem
	for len(b) > 0 {
		e, rest, err := readElem(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

func parseInt(e elem) (int, error) {
	if e.tag != 0x02 || len(e.content) == 0 || len(e.content) > 4 {
		return 0, errDER
	}
	v := 0
	for _, c := range e.content {
		v = v<<8 | int(c)
	}
	if e.content[0]&0x80 != 0 {
		return 0, errDER
	}
	return v, nil
}

func sameOID(e elem, want []byte) bool {
	return e.tag == 0x06 && bytes.Equal(e.full, want)
}
