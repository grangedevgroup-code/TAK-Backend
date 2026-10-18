package server

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

type DropRule struct {
	Type      string `json:"type"`
	Detail    string `json:"detail,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
}

type ImageFilters struct {
	Thumbnail       bool `json:"thumbnail,omitempty"`
	ThumbnailPixels int  `json:"thumbnailPixels,omitempty"`
	URLAdd          bool `json:"urlAdd,omitempty"`
	OverwriteURL    bool `json:"overwriteUrl,omitempty"`
}

type dropCounter struct {
	mu     sync.Mutex
	window map[string]*dropWindow
}

type dropWindow struct {
	start time.Time
	n     int
}

func (d *dropCounter) over(key string, limit int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.window == nil {
		d.window = map[string]*dropWindow{}
	}
	now := time.Now()
	w := d.window[key]
	if w == nil || now.Sub(w.start) > time.Minute {
		if len(d.window) > 50000 {
			d.window = map[string]*dropWindow{}
		}
		w = &dropWindow{start: now}
		d.window[key] = w
	}
	w.n++
	return w.n > limit
}

func (s *Server) dropByRules(m *Message, rules []DropRule) bool {
	e := m.Event
	if e.IsControl() || e.IsDelete() {
		return false
	}
	for _, r := range rules {
		if r.Type == "" || !typeMatches(e.Type, []string{r.Type}) {
			continue
		}
		if r.Detail != "" && e.D(r.Detail) == nil {
			continue
		}
		if r.Threshold > 0 {
			src := ""
			if m.Source != nil {
				src = strconv.FormatUint(m.Source.ID, 10)
			}
			if !s.drops.over(src+"|"+r.Type+"|"+r.Detail, r.Threshold) {
				continue
			}
		}
		return true
	}
	return false
}

func scrubEvent(e *cot.Event, action string) bool {
	p := &e.Point
	bad := math.IsNaN(p.Lat) || math.IsNaN(p.Lon) || p.Lat < -90 || p.Lat > 90 || p.Lon < -180 || p.Lon > 180 || e.UID == "" || e.Type == ""
	if bad && !strings.EqualFold(action, "overwrite") {
		return false
	}
	if bad {
		if e.UID == "" || e.Type == "" {
			return false
		}
		p.Lat, p.Lon = math.Max(-90, math.Min(90, nanZero(p.Lat))), math.Max(-180, math.Min(180, nanZero(p.Lon)))
	}
	if math.IsNaN(p.Hae) || math.IsInf(p.Hae, 0) {
		p.Hae = 9999999
	}
	if math.IsNaN(p.Ce) || p.Ce < 0 {
		p.Ce = 9999999
	}
	if math.IsNaN(p.Le) || p.Le < 0 {
		p.Le = 9999999
	}
	if !e.Stale.IsZero() && !e.Time.IsZero() && e.Stale.Before(e.Time) {
		e.Stale = e.Time.Add(time.Minute)
	}
	return true
}

func nanZero(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func thumbnail(img image.Image, maxSide int) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= maxSide && h <= maxSide {
		return img
	}
	scale := float64(maxSide) / float64(max(w, h))
	nw, nh := max(1, int(float64(w)*scale)), max(1, int(float64(h)*scale))
	out := image.NewRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		y0, y1 := b.Min.Y+int(float64(y)/scale), b.Min.Y+int(float64(y+1)/scale)
		for x := 0; x < nw; x++ {
			x0, x1 := b.Min.X+int(float64(x)/scale), b.Min.X+int(float64(x+1)/scale)
			var r, g, bl, a, n uint64
			for yy := y0; yy < max(y1, y0+1) && yy < b.Max.Y; yy++ {
				for xx := x0; xx < max(x1, x0+1) && xx < b.Max.X; xx++ {
					cr, cg, cb, ca := img.At(xx, yy).RGBA()
					r, g, bl, a, n = r+uint64(cr), g+uint64(cg), bl+uint64(cb), a+uint64(ca), n+1
				}
			}
			if n > 0 {
				out.Set(x, y, color.RGBA64{uint16(r / n), uint16(g / n), uint16(bl / n), uint16(a / n)})
			}
		}
	}
	return out
}

func (s *Server) processImages(e *cot.Event, f ImageFilters) {
	n := e.D("image")
	if n == nil || strings.TrimSpace(n.Text) == "" {
		return
	}
	data, mime := imageOf(e)
	if data == nil {
		return
	}
	if f.URLAdd {
		name := e.UID + "-image" + map[string]string{"image/png": ".png", "image/gif": ".gif"}[mime]
		if !strings.Contains(name, ".") {
			name += ".jpg"
		}
		hash, err := s.res.blobs.PutBytes(data)
		if err == nil {
			uid := "image-" + hash
			if _, ok := s.res.Get(uid); !ok {
				s.res.Put(Resource{UID: uid, Hash: hash, Name: name, MIMEType: mime, Size: int64(len(data)), Keywords: []string{"image"}, Tool: "public",
					Submitter: s.Config().Name, Submitted: time.Now().UTC(), Expiration: -1})
			}
			n.SetAttr("url", s.clientContentURL(uid))
		}
	}
	if f.Thumbnail {
		px := f.ThumbnailPixels
		if px <= 0 {
			px = 128
		}
		if img, _, err := image.Decode(bytes.NewReader(data)); err == nil {
			var buf bytes.Buffer
			if jpeg.Encode(&buf, thumbnail(img, px), &jpeg.Options{Quality: 75}) == nil {
				thumb := base64.StdEncoding.EncodeToString(buf.Bytes())
				if f.URLAdd {
					if hash, err := s.res.blobs.PutBytes(buf.Bytes()); err == nil {
						uid := "thumb-" + hash
						if _, ok := s.res.Get(uid); !ok {
							s.res.Put(Resource{UID: uid, Hash: hash, Name: e.UID + "-thumb.jpg", MIMEType: "image/jpeg", Size: int64(buf.Len()), Keywords: []string{"image", "thumbnail"},
								Tool: "public", Submitter: s.Config().Name, Submitted: time.Now().UTC(), Expiration: -1})
						}
						n.SetAttr("thumburl", s.clientContentURL(uid))
					}
				}
				n.Text = thumb
				n.SetAttr("mime", "image/jpeg")
			}
		}
	}
	if f.URLAdd && f.OverwriteURL {
		n.Text = ""
	}
}
