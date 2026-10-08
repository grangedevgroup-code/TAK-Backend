package media

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type Track struct {
	Media       string
	PayloadType uint8
	Codec       string
	ClockRate   int
	Channels    int
	Fmtp        map[string]string
	Control     string
	Lines       []string
}

type Description struct {
	Name   string
	Tracks []*Track
}

func ParseSDP(body []byte) (*Description, error) {
	d := &Description{}
	var cur *Track
	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		key, val := line[0], line[2:]
		switch {
		case key == 's' && cur == nil:
			d.Name = val
		case key == 'm':
			f := strings.Fields(val)
			if len(f) < 4 {
				return nil, fmt.Errorf("bad media line %q", line)
			}
			pt, err := strconv.Atoi(f[3])
			if err != nil || pt < 0 || pt > 127 {
				return nil, fmt.Errorf("bad payload type in %q", line)
			}
			cur = &Track{Media: f[0], PayloadType: uint8(pt), Fmtp: map[string]string{}}
			d.Tracks = append(d.Tracks, cur)
		case cur == nil:
		case key == 'a' && strings.HasPrefix(val, "control:"):
			cur.Control = strings.TrimPrefix(val, "control:")
		case key == 'a' && strings.HasPrefix(val, "rtpmap:"):
			f := strings.Fields(strings.TrimPrefix(val, "rtpmap:"))
			if len(f) == 2 {
				parts := strings.Split(f[1], "/")
				cur.Codec = strings.ToUpper(parts[0])
				if len(parts) > 1 {
					cur.ClockRate, _ = strconv.Atoi(parts[1])
				}
				if len(parts) > 2 {
					cur.Channels, _ = strconv.Atoi(parts[2])
				}
			}
			cur.Lines = append(cur.Lines, line)
		case key == 'a' && strings.HasPrefix(val, "fmtp:"):
			rest := strings.TrimPrefix(val, "fmtp:")
			if i := strings.IndexByte(rest, ' '); i >= 0 {
				for _, kv := range strings.Split(rest[i+1:], ";") {
					k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
					if k != "" {
						cur.Fmtp[strings.ToLower(k)] = v
					}
				}
			}
			cur.Lines = append(cur.Lines, line)
		case key == 'c':
		default:
			cur.Lines = append(cur.Lines, line)
		}
	}
	if len(d.Tracks) == 0 {
		return nil, fmt.Errorf("the description has no media")
	}
	for _, t := range d.Tracks {
		if t.ClockRate == 0 {
			t.ClockRate = staticClock(t.PayloadType)
		}
		if t.Codec == "" {
			t.Codec = staticCodec(t.PayloadType)
		}
	}
	return d, nil
}

func staticClock(pt uint8) int {
	switch pt {
	case 0, 8, 9:
		return 8000
	case 14:
		return 90000
	case 26, 32, 33:
		return 90000
	}
	return 90000
}

func staticCodec(pt uint8) string {
	switch pt {
	case 0:
		return "PCMU"
	case 8:
		return "PCMA"
	case 14:
		return "MPA"
	case 26:
		return "JPEG"
	case 32:
		return "MPV"
	case 33:
		return "MP2T"
	}
	return ""
}

func (d *Description) Marshal(name string) []byte {
	var b strings.Builder
	b.WriteString("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\n")
	fmt.Fprintf(&b, "s=%s\r\n", sanitizeLine(firstNonEmpty(name, d.Name, "Stream")))
	b.WriteString("c=IN IP4 0.0.0.0\r\nt=0 0\r\na=control:*\r\n")
	for i, t := range d.Tracks {
		fmt.Fprintf(&b, "m=%s 0 RTP/AVP %d\r\n", t.Media, t.PayloadType)
		for _, l := range t.Lines {
			if strings.HasPrefix(l, "a=control:") || strings.HasPrefix(l, "a=range") {
				continue
			}
			b.WriteString(l)
			b.WriteString("\r\n")
		}
		fmt.Fprintf(&b, "a=control:trackID=%d\r\n", i)
	}
	return []byte(b.String())
}

func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (t *Track) H264Params() (sps, pps []byte) {
	for _, p := range strings.Split(t.Fmtp["sprop-parameter-sets"], ",") {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
		if err != nil || len(data) == 0 {
			continue
		}
		switch data[0] & 0x1f {
		case 7:
			sps = data
		case 8:
			pps = data
		}
	}
	return sps, pps
}
