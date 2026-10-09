package ldap

import (
	"bufio"
	"errors"
	"io"
)

var errBER = errors.New("ldap: malformed message")

const (
	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagSequence    = 0x30
	tagSet         = 0x31
)

type element struct {
	tag      byte
	content  []byte
	children []element
}

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

func tlv(tag byte, content []byte) []byte {
	b := []byte{tag}
	b = appendLength(b, len(content))
	return append(b, content...)
}

func seq(tag byte, parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return tlv(tag, content)
}

func encInt(tag byte, v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		if (v >= -128 && v < 128) || len(b) >= 8 {
			break
		}
		v >>= 8
	}
	return tlv(tag, b)
}

func encStr(tag byte, s string) []byte { return tlv(tag, []byte(s)) }

func encBool(v bool) []byte {
	if v {
		return tlv(tagBoolean, []byte{0xff})
	}
	return tlv(tagBoolean, []byte{0})
}

func parseOne(b []byte) (element, []byte, error) {
	if len(b) < 2 {
		return element{}, nil, errBER
	}
	tag := b[0]
	if tag&0x1f == 0x1f {
		return element{}, nil, errBER
	}
	n := int(b[1])
	off := 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return element{}, nil, errBER
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(b[2+i])
		}
		off += k
	}
	if n < 0 || off+n > len(b) {
		return element{}, nil, errBER
	}
	e := element{tag: tag, content: b[off : off+n]}
	if tag&0x20 != 0 {
		rest := e.content
		for len(rest) > 0 {
			c, r, err := parseOne(rest)
			if err != nil {
				return element{}, nil, err
			}
			e.children = append(e.children, c)
			rest = r
		}
	}
	return e, b[off+n:], nil
}

func readMessage(r *bufio.Reader, limit int) (element, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return element{}, err
	}
	first, err := r.ReadByte()
	if err != nil {
		return element{}, err
	}
	head := []byte{tag, first}
	n := int(first)
	if first&0x80 != 0 {
		k := int(first & 0x7f)
		if k == 0 || k > 4 {
			return element{}, errBER
		}
		lb := make([]byte, k)
		if _, err := io.ReadFull(r, lb); err != nil {
			return element{}, err
		}
		head = append(head, lb...)
		n = 0
		for _, c := range lb {
			n = n<<8 | int(c)
		}
	}
	if n < 0 || n > limit {
		return element{}, errors.New("ldap: response too large")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return element{}, err
	}
	e, _, err := parseOne(append(head, body...))
	return e, err
}

func (e element) int() int64 {
	var v int64
	for i, c := range e.content {
		if i == 0 && c&0x80 != 0 {
			v = -1
		}
		v = v<<8 | int64(c)
	}
	return v
}

func (e element) str() string { return string(e.content) }
