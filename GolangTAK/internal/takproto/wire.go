package takproto

import (
	"encoding/binary"
	"errors"
	"math"
)

var (
	ErrTruncated = errors.New("takproto: truncated message")
	ErrOverflow  = errors.New("takproto: varint overflow")
	ErrWireType  = errors.New("takproto: unsupported wire type")
)

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

func AppendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func ReadVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b); i++ {
		if i == 10 {
			return 0, 0, ErrOverflow
		}
		c := b[i]
		if i == 9 && c > 1 {
			return 0, 0, ErrOverflow
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, ErrTruncated
}

func appendTag(b []byte, field int, wire int) []byte {
	return AppendVarint(b, uint64(field)<<3|uint64(wire))
}

func appendString(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	b = appendTag(b, field, wireBytes)
	b = AppendVarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendBytes(b []byte, field int, v []byte) []byte {
	b = appendTag(b, field, wireBytes)
	b = AppendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendUint(b []byte, field int, v uint64) []byte {
	if v == 0 {
		return b
	}
	b = appendTag(b, field, wireVarint)
	return AppendVarint(b, v)
}

func appendDouble(b []byte, field int, f float64) []byte {
	if f == 0 && !math.Signbit(f) {
		return b
	}
	b = appendTag(b, field, wireFixed64)
	return binary.LittleEndian.AppendUint64(b, math.Float64bits(f))
}

type field struct {
	num   int
	wire  int
	u     uint64
	bytes []byte
}

func eachField(b []byte, fn func(f field) error) error {
	for len(b) > 0 {
		key, n, err := ReadVarint(b)
		if err != nil {
			return err
		}
		b = b[n:]
		f := field{num: int(key >> 3), wire: int(key & 7)}
		if f.num <= 0 {
			return ErrWireType
		}
		switch f.wire {
		case wireVarint:
			v, n, err := ReadVarint(b)
			if err != nil {
				return err
			}
			f.u = v
			b = b[n:]
		case wireFixed64:
			if len(b) < 8 {
				return ErrTruncated
			}
			f.u = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case wireFixed32:
			if len(b) < 4 {
				return ErrTruncated
			}
			f.u = uint64(binary.LittleEndian.Uint32(b))
			b = b[4:]
		case wireBytes:
			l, n, err := ReadVarint(b)
			if err != nil {
				return err
			}
			b = b[n:]
			if l > uint64(len(b)) {
				return ErrTruncated
			}
			f.bytes = b[:l]
			b = b[l:]
		default:
			return ErrWireType
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

func (f field) double() float64 {
	if f.wire == wireFixed64 {
		return math.Float64frombits(f.u)
	}
	if f.wire == wireFixed32 {
		return float64(math.Float32frombits(uint32(f.u)))
	}
	return 0
}

func (f field) str() string {
	if f.wire != wireBytes {
		return ""
	}
	return string(f.bytes)
}

func (f field) uint() uint64 {
	if f.wire == wireVarint || f.wire == wireFixed64 || f.wire == wireFixed32 {
		return f.u
	}
	return 0
}
