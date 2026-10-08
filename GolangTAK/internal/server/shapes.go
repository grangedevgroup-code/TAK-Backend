package server

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

type shapeView struct {
	Points [][2]float64 `json:"points,omitempty"`
	Closed bool         `json:"closed,omitempty"`
	Radius float64      `json:"radius,omitempty"`
	Minor  float64      `json:"minor,omitempty"`
	Angle  float64      `json:"angle,omitempty"`
	Stroke string       `json:"stroke,omitempty"`
	Fill   string       `json:"fill,omitempty"`
	Width  float64      `json:"width,omitempty"`
	Route  bool         `json:"route,omitempty"`
}

func argbColor(v string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return ""
	}
	u := uint32(n)
	a := float64(u>>24) / 255
	return fmt.Sprintf("rgba(%d,%d,%d,%.2f)", (u>>16)&0xff, (u>>8)&0xff, u&0xff, a)
}

func parsePoint(s string) ([2]float64, bool) {
	f := strings.Split(s, ",")
	if len(f) < 2 {
		return [2]float64{}, false
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(f[0]), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(f[1]), 64)
	if err1 != nil || err2 != nil || math.Abs(lat) > 90 || math.Abs(lon) > 180 {
		return [2]float64{}, false
	}
	return [2]float64{lat, lon}, true
}

func numAttr(e *cot.Event, path, attr string) (float64, bool) {
	n := e.D(path)
	if n == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(n.Attr(attr)), 64)
	return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
}

func shapeOf(e *cot.Event) *shapeView {
	if e.Detail == nil {
		return nil
	}
	t := e.Type
	sv := &shapeView{}
	if n := e.D("strokeColor"); n != nil {
		sv.Stroke = argbColor(n.Attr("value"))
	}
	if n := e.D("fillColor"); n != nil {
		sv.Fill = argbColor(n.Attr("value"))
	}
	if w, ok := numAttr(e, "strokeWeight", "value"); ok {
		sv.Width = w
	}
	for _, l := range e.Detail.All("link") {
		if p, ok := parsePoint(l.Attr("point")); ok {
			sv.Points = append(sv.Points, p)
		}
	}
	switch {
	case strings.HasPrefix(t, "b-m-r"):
		sv.Route = true
		if n := e.D("link_attr"); n != nil && sv.Stroke == "" {
			sv.Stroke = argbColor(n.Attr("color"))
		}
	case strings.HasPrefix(t, "u-rb-a"):
		rng, ok1 := numAttr(e, "range", "value")
		brg, ok2 := numAttr(e, "bearing", "value")
		if !ok1 || !ok2 || rng <= 0 {
			return nil
		}
		lat, lon := destination(e.Point.Lat, e.Point.Lon, rng, brg)
		sv.Points = [][2]float64{{e.Point.Lat, e.Point.Lon}, {lat, lon}}
	case strings.HasPrefix(t, "u-d-c") || strings.HasPrefix(t, "u-r-b-c"):
		el := e.D("shape", "ellipse")
		if el == nil {
			return nil
		}
		major, err := strconv.ParseFloat(el.Attr("major"), 64)
		if err != nil || major <= 0 {
			return nil
		}
		sv.Radius = major
		sv.Minor, _ = strconv.ParseFloat(el.Attr("minor"), 64)
		sv.Angle, _ = strconv.ParseFloat(el.Attr("angle"), 64)
		sv.Points = nil
		sv.Closed = true
		if ls := e.D("shape", "link", "Style", "LineStyle", "color"); ls != nil && sv.Stroke == "" {
			sv.Stroke = kmlColor(ls.Text)
		}
	case strings.HasPrefix(t, "u-d-r"):
		sv.Closed = true
	case strings.HasPrefix(t, "u-d-"):
		if sv.Fill != "" || (len(sv.Points) > 2 && sv.Points[0] == sv.Points[len(sv.Points)-1]) {
			sv.Closed = true
		}
		if c := e.D("shape", "polyline"); c != nil && c.Attr("closed") == "true" {
			sv.Closed = true
		}
	default:
		return nil
	}
	if sv.Radius == 0 && len(sv.Points) < 2 {
		return nil
	}
	if len(sv.Points) > 2000 {
		sv.Points = sv.Points[:2000]
	}
	return sv
}

func kmlColor(v string) string {
	v = strings.TrimSpace(v)
	if len(v) != 8 {
		return ""
	}
	n, err := strconv.ParseUint(v, 16, 32)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("rgba(%d,%d,%d,%.2f)", n&0xff, (n>>8)&0xff, (n>>16)&0xff, float64(n>>24)/255)
}

func medevacOf(e *cot.Event) map[string]string {
	n := e.D("_medevac_")
	if n == nil {
		return nil
	}
	out := map[string]string{}
	for _, a := range n.Attrs {
		if v := strings.TrimSpace(a.Value); v != "" && len(out) < 64 {
			out[a.Name] = v
		}
	}
	for _, c := range n.Children {
		if c.Name == "zMistsMap" {
			for i, z := range c.All("zMist") {
				for _, a := range z.Attrs {
					if v := strings.TrimSpace(a.Value); v != "" {
						out[fmt.Sprintf("zmist%d_%s", i+1, a.Name)] = v
					}
				}
			}
		}
	}
	return out
}

func imageOf(e *cot.Event) ([]byte, string) {
	n := e.D("image")
	if n == nil || strings.TrimSpace(n.Text) == "" {
		return nil, ""
	}
	data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(n.Text), ""))
	if err != nil || len(data) == 0 {
		return nil, ""
	}
	mime := http.DetectContentType(data)
	if !strings.HasPrefix(mime, "image/") {
		return nil, ""
	}
	return data, mime
}

func (s *Server) apiEventImage(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	m := s.hub.CachedEvent(r.PathValue("uid"))
	if m == nil || (!m.Everyone && !id.Admin && !s.visibleTo(id, m.Groups)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no image for that object"})
		return
	}
	data, mime := imageOf(m.Event)
	if data == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no image for that object"})
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Write(data)
}
