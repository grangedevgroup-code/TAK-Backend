package media

import (
	"encoding/binary"
	"errors"
	"math"
)

type amfObject map[string]any

type amfUndefined struct{}

var errAMF = errors.New("bad amf0 data")

func amfDecode(b []byte) ([]any, error) {
	var out []any
	for len(b) > 0 {
		v, n, err := amfValue(b, 0)
		if err != nil {
			return out, err
		}
		out = append(out, v)
		b = b[n:]
	}
	return out, nil
}

func amfString(b []byte, long bool) (string, int, error) {
	if long {
		if len(b) < 4 {
			return "", 0, errAMF
		}
		n := int(binary.BigEndian.Uint32(b))
		if n > len(b)-4 {
			return "", 0, errAMF
		}
		return string(b[4 : 4+n]), 4 + n, nil
	}
	if len(b) < 2 {
		return "", 0, errAMF
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > len(b)-2 {
		return "", 0, errAMF
	}
	return string(b[2 : 2+n]), 2 + n, nil
}

func amfProps(b []byte, depth int) (amfObject, int, error) {
	obj := amfObject{}
	pos := 0
	for {
		if len(b)-pos >= 3 && b[pos] == 0 && b[pos+1] == 0 && b[pos+2] == 9 {
			return obj, pos + 3, nil
		}
		k, n, err := amfString(b[pos:], false)
		if err != nil {
			return nil, 0, err
		}
		pos += n
		v, n, err := amfValue(b[pos:], depth+1)
		if err != nil {
			return nil, 0, err
		}
		pos += n
		if len(obj) < 1024 {
			obj[k] = v
		}
	}
}

func amfValue(b []byte, depth int) (any, int, error) {
	if len(b) == 0 || depth > 16 {
		return nil, 0, errAMF
	}
	switch b[0] {
	case 0:
		if len(b) < 9 {
			return nil, 0, errAMF
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b[1:])), 9, nil
	case 1:
		if len(b) < 2 {
			return nil, 0, errAMF
		}
		return b[1] != 0, 2, nil
	case 2:
		s, n, err := amfString(b[1:], false)
		return s, n + 1, err
	case 12:
		s, n, err := amfString(b[1:], true)
		return s, n + 1, err
	case 3:
		o, n, err := amfProps(b[1:], depth)
		return o, n + 1, err
	case 8:
		if len(b) < 5 {
			return nil, 0, errAMF
		}
		o, n, err := amfProps(b[5:], depth)
		return o, n + 5, err
	case 5:
		return nil, 1, nil
	case 6:
		return amfUndefined{}, 1, nil
	case 10:
		if len(b) < 5 {
			return nil, 0, errAMF
		}
		count := int(binary.BigEndian.Uint32(b[1:]))
		pos := 5
		var arr []any
		for i := 0; i < count; i++ {
			v, n, err := amfValue(b[pos:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			pos += n
			if len(arr) < 1024 {
				arr = append(arr, v)
			}
		}
		return arr, pos, nil
	case 11:
		if len(b) < 11 {
			return nil, 0, errAMF
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b[1:])), 11, nil
	}
	return nil, 0, errAMF
}

func amfEncode(vals ...any) []byte {
	var out []byte
	for _, v := range vals {
		out = amfAppend(out, v)
	}
	return out
}

func amfAppend(out []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(out, 5)
	case amfUndefined:
		return append(out, 6)
	case float64:
		out = append(out, 0)
		return binary.BigEndian.AppendUint64(out, math.Float64bits(x))
	case int:
		return amfAppend(out, float64(x))
	case bool:
		if x {
			return append(out, 1, 1)
		}
		return append(out, 1, 0)
	case string:
		out = append(out, 2)
		out = binary.BigEndian.AppendUint16(out, uint16(len(x)))
		return append(out, x...)
	case amfObject:
		out = append(out, 3)
		for _, k := range sortedKeys(x) {
			out = binary.BigEndian.AppendUint16(out, uint16(len(k)))
			out = append(out, k...)
			out = amfAppend(out, x[k])
		}
		return append(out, 0, 0, 9)
	}
	return append(out, 5)
}

func sortedKeys(m amfObject) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
