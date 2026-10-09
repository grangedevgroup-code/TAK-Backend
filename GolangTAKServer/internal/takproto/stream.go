package takproto

import (
	"bytes"
	"errors"
	"io"
)

var ErrTooLarge = errors.New("takproto: message exceeds size limit")

const DefaultMax = 8 << 20

type Frame struct {
	Proto bool
	Data  []byte
}

func AppendStreamFrame(dst, payload []byte) []byte {
	dst = append(dst, Magic)
	dst = AppendVarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}

func MeshFrame(payload []byte) []byte {
	b := make([]byte, 0, len(payload)+3)
	b = append(b, Magic, Version, Magic)
	return append(b, payload...)
}

func ParseMesh(b []byte) ([]byte, bool) {
	if len(b) < 3 || b[0] != Magic {
		return nil, false
	}
	v, n, err := ReadVarint(b[1:])
	if err != nil || v == 0 || 1+n >= len(b) || b[1+n] != Magic {
		return nil, false
	}
	return b[2+n:], true
}

type scanState struct {
	pos   int
	depth int
}

type Reader struct {
	r     io.Reader
	buf   []byte
	start int
	end   int
	max   int
	scan  scanState
	err   error
}

func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 {
		max = DefaultMax
	}
	size := 64 << 10
	if size > max+64 {
		size = max + 64
	}
	return &Reader{r: r, buf: make([]byte, size), max: max}
}

func (r *Reader) Buffered() []byte { return r.buf[r.start:r.end] }

func (r *Reader) fill() error {
	if r.err != nil {
		return r.err
	}
	if r.start > 0 && (r.start == r.end || r.start > len(r.buf)/2) {
		copy(r.buf, r.buf[r.start:r.end])
		r.end -= r.start
		r.start = 0
	}
	if r.end == len(r.buf) {
		if len(r.buf) >= r.max+64 {
			return ErrTooLarge
		}
		size := len(r.buf) * 2
		if size > r.max+64 {
			size = r.max + 64
		}
		nb := make([]byte, size)
		copy(nb, r.buf[r.start:r.end])
		r.end -= r.start
		r.start = 0
		r.buf = nb
	}
	n, err := r.r.Read(r.buf[r.end:])
	r.end += n
	if err != nil {
		if te, ok := err.(interface{ Timeout() bool }); !ok || !te.Timeout() {
			r.err = err
		}
		if n > 0 {
			return nil
		}
		return err
	}
	return nil
}

var markers = []string{"<!--", "<![CDATA[", "<?", "<!", "</"}

func ambiguous(rest []byte) bool {
	for _, m := range markers {
		if len(rest) < len(m) && bytes.HasPrefix([]byte(m), rest) {
			return true
		}
	}
	return false
}

func scanElement(b []byte, st *scanState) (int, bool) {
	for st.pos < len(b) {
		if b[st.pos] != '<' {
			j := bytes.IndexByte(b[st.pos:], '<')
			if j < 0 {
				st.pos = len(b)
				return 0, false
			}
			st.pos += j
			continue
		}
		rest := b[st.pos:]
		if ambiguous(rest) {
			return 0, false
		}
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			j := bytes.Index(rest[4:], []byte("-->"))
			if j < 0 {
				return 0, false
			}
			st.pos += 4 + j + 3
		case bytes.HasPrefix(rest, []byte("<![CDATA[")):
			j := bytes.Index(rest[9:], []byte("]]>"))
			if j < 0 {
				return 0, false
			}
			st.pos += 9 + j + 3
		case bytes.HasPrefix(rest, []byte("<?")):
			j := bytes.Index(rest[2:], []byte("?>"))
			if j < 0 {
				return 0, false
			}
			st.pos += 2 + j + 2
		case bytes.HasPrefix(rest, []byte("<!")):
			j := bytes.IndexByte(rest, '>')
			if j < 0 {
				return 0, false
			}
			st.pos += j + 1
		case bytes.HasPrefix(rest, []byte("</")):
			j := bytes.IndexByte(rest, '>')
			if j < 0 {
				return 0, false
			}
			st.pos += j + 1
			st.depth--
			if st.depth <= 0 {
				return st.pos, true
			}
		default:
			var quote byte
			j := -1
			for k := 1; k < len(rest); k++ {
				c := rest[k]
				if quote != 0 {
					if c == quote {
						quote = 0
					}
					continue
				}
				if c == '"' || c == '\'' {
					quote = c
					continue
				}
				if c == '>' {
					j = k
					break
				}
			}
			if j < 0 {
				return 0, false
			}
			self := rest[j-1] == '/'
			st.pos += j + 1
			if !self {
				st.depth++
			} else if st.depth == 0 {
				return st.pos, true
			}
		}
	}
	return 0, false
}

func (r *Reader) Next() (Frame, error) {
	for {
		for r.start < r.end {
			c := r.buf[r.start]
			if c == Magic {
				f, ok, err := r.protoFrame()
				if err != nil {
					return Frame{}, err
				}
				if ok {
					return f, nil
				}
				break
			}
			if c != '<' {
				j := r.start + 1
				for j < r.end && r.buf[j] != '<' && r.buf[j] != Magic {
					j++
				}
				r.start = j
				continue
			}
			rest := r.buf[r.start:r.end]
			if len(rest) < 2 {
				break
			}
			if rest[1] == '?' || rest[1] == '!' {
				if ambiguous(rest) {
					break
				}
				var term []byte
				switch {
				case bytes.HasPrefix(rest, []byte("<?")):
					term = []byte("?>")
				case bytes.HasPrefix(rest, []byte("<!--")):
					term = []byte("-->")
				default:
					term = []byte(">")
				}
				j := bytes.Index(rest[2:], term)
				if j < 0 {
					if len(rest) > r.max {
						return Frame{}, ErrTooLarge
					}
					break
				}
				r.start += 2 + j + len(term)
				continue
			}
			if rest[1] == '/' {
				j := bytes.IndexByte(rest, '>')
				if j < 0 {
					break
				}
				r.start += j + 1
				continue
			}
			end, ok := scanElement(rest, &r.scan)
			if !ok {
				if r.scan.pos > r.max || len(rest) > r.max {
					return Frame{}, ErrTooLarge
				}
				break
			}
			if end > r.max {
				return Frame{}, ErrTooLarge
			}
			data := make([]byte, end)
			copy(data, rest[:end])
			r.start += end
			r.scan = scanState{}
			return Frame{Data: data}, nil
		}
		if err := r.fill(); err != nil {
			return Frame{}, err
		}
	}
}

func (r *Reader) protoFrame() (Frame, bool, error) {
	b := r.buf[r.start+1 : r.end]
	l, n, err := ReadVarint(b)
	if err == ErrTruncated {
		return Frame{}, false, nil
	}
	if err != nil {
		return Frame{}, false, err
	}
	if l > uint64(r.max) {
		return Frame{}, false, ErrTooLarge
	}
	if uint64(len(b)-n) < l {
		return Frame{}, false, nil
	}
	data := make([]byte, l)
	copy(data, b[n:n+int(l)])
	r.start += 1 + n + int(l)
	return Frame{Proto: true, Data: data}, true, nil
}
