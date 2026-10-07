package mqtt

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const (
	typeConnect     = 1
	typeConnack     = 2
	typePublish     = 3
	typePuback      = 4
	typePubrec      = 5
	typePubrel      = 6
	typePubcomp     = 7
	typeSubscribe   = 8
	typeSuback      = 9
	typeUnsubscribe = 10
	typeUnsuback    = 11
	typePingreq     = 12
	typePingresp    = 13
	typeDisconnect  = 14
)

var (
	ErrMalformed = errors.New("mqtt: malformed packet")
	ErrTooLarge  = errors.New("mqtt: packet too large")
)

type packet struct {
	kind  byte
	flags byte
	body  []byte
}

func readPacket(r *bufio.Reader, limit int) (packet, error) {
	h, err := r.ReadByte()
	if err != nil {
		return packet{}, err
	}
	n := 0
	mult := 1
	for i := 0; ; i++ {
		if i == 4 {
			return packet{}, ErrMalformed
		}
		b, err := r.ReadByte()
		if err != nil {
			return packet{}, err
		}
		n += int(b&0x7f) * mult
		if b&0x80 == 0 {
			break
		}
		mult *= 128
	}
	if n > limit {
		return packet{}, ErrTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return packet{}, err
	}
	return packet{kind: h >> 4, flags: h & 0x0f, body: body}, nil
}

func encode(kind, flags byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := []byte{kind<<4 | flags}
	x := n
	for {
		b := byte(x % 128)
		x /= 128
		if x > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if x == 0 {
			break
		}
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func str(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	copy(b[2:], s)
	return b
}

func u16(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) uint16() uint16 {
	if r.err != nil || len(r.b) < 2 {
		r.err = ErrMalformed
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *reader) byte() byte {
	if r.err != nil || len(r.b) < 1 {
		r.err = ErrMalformed
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *reader) bytes() []byte {
	n := int(r.uint16())
	if r.err != nil || len(r.b) < n {
		r.err = ErrMalformed
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) string() string { return string(r.bytes()) }

func publishPacket(topic string, payload []byte, qos byte, id uint16, retain bool) []byte {
	flags := qos << 1
	if retain {
		flags |= 1
	}
	if qos > 0 {
		return encode(typePublish, flags, str(topic), u16(id), payload)
	}
	return encode(typePublish, flags, str(topic), payload)
}

func validTopic(t string) bool {
	return t != "" && len(t) <= 65535 && !strings.ContainsAny(t, "+#\x00")
}

func validFilter(f string) bool {
	if f == "" || len(f) > 65535 || strings.ContainsRune(f, 0) {
		return false
	}
	levels := strings.Split(f, "/")
	for i, l := range levels {
		if strings.Contains(l, "#") && (l != "#" || i != len(levels)-1) {
			return false
		}
		if strings.Contains(l, "+") && l != "+" {
			return false
		}
	}
	return true
}

func Match(filter, topic string) bool {
	if strings.HasPrefix(topic, "$") && (strings.HasPrefix(filter, "+") || strings.HasPrefix(filter, "#")) {
		return false
	}
	fl := strings.Split(filter, "/")
	tl := strings.Split(topic, "/")
	for i, f := range fl {
		if f == "#" {
			return true
		}
		if i >= len(tl) {
			return false
		}
		if f != "+" && f != tl[i] {
			return false
		}
	}
	return len(fl) == len(tl)
}
