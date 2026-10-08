package mumble

import (
	"encoding/binary"
	"errors"
	"math"
)

type pbField struct {
	num  int
	wire int
	v    uint64
	b    []byte
}

type pbMsg []pbField

var errProto = errors.New("bad protobuf message")

func pbParse(b []byte) (pbMsg, error) {
	var out pbMsg
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errProto
		}
		b = b[n:]
		f := pbField{num: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errProto
			}
			f.v, b = v, b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errProto
			}
			f.v, b = binary.LittleEndian.Uint64(b), b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, errProto
			}
			f.b, b = b[n:n+int(l)], b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errProto
			}
			f.v, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		default:
			return nil, errProto
		}
		if len(out) < 4096 {
			out = append(out, f)
		}
	}
	return out, nil
}

func (m pbMsg) has(num int) bool {
	for _, f := range m {
		if f.num == num {
			return true
		}
	}
	return false
}

func (m pbMsg) uint(num int) uint64 {
	var v uint64
	for _, f := range m {
		if f.num == num && f.wire != 2 {
			v = f.v
		}
	}
	return v
}

func (m pbMsg) bool(num int) bool { return m.uint(num) != 0 }

func (m pbMsg) str(num int) string {
	var s string
	for _, f := range m {
		if f.num == num && f.wire == 2 {
			s = string(f.b)
		}
	}
	return s
}

func (m pbMsg) bytes(num int) []byte {
	var b []byte
	for _, f := range m {
		if f.num == num && f.wire == 2 {
			b = f.b
		}
	}
	return b
}

func (m pbMsg) uints(num int) []uint64 {
	var out []uint64
	for _, f := range m {
		if f.num != num {
			continue
		}
		if f.wire == 2 {
			p := f.b
			for len(p) > 0 {
				v, n := binary.Uvarint(p)
				if n <= 0 {
					break
				}
				out = append(out, v)
				p = p[n:]
			}
			continue
		}
		out = append(out, f.v)
	}
	return out
}

func (m pbMsg) all(num int) [][]byte {
	var out [][]byte
	for _, f := range m {
		if f.num == num && f.wire == 2 {
			out = append(out, f.b)
		}
	}
	return out
}

type pbBuf []byte

func (b pbBuf) key(num, wire int) pbBuf { return binary.AppendUvarint(b, uint64(num<<3|wire)) }

func (b pbBuf) Uint(num int, v uint64) pbBuf {
	return binary.AppendUvarint(b.key(num, 0), v)
}

func (b pbBuf) Int(num int, v int64) pbBuf {
	return binary.AppendUvarint(b.key(num, 0), uint64(v))
}

func (b pbBuf) Bool(num int, v bool) pbBuf {
	if v {
		return b.Uint(num, 1)
	}
	return b.Uint(num, 0)
}

func (b pbBuf) Bytes(num int, v []byte) pbBuf {
	b = binary.AppendUvarint(b.key(num, 2), uint64(len(v)))
	return append(b, v...)
}

func (b pbBuf) Str(num int, v string) pbBuf { return b.Bytes(num, []byte(v)) }

func (b pbBuf) Float(num int, v float32) pbBuf {
	return binary.LittleEndian.AppendUint32(b.key(num, 5), math.Float32bits(v))
}
