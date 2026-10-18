package server

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

type MessageFilters struct {
	DropTypes      []string     `json:"dropTypes,omitempty"`
	StripDetails   []string     `json:"stripDetails,omitempty"`
	DropRules      []DropRule   `json:"dropRules,omitempty"`
	Images         ImageFilters `json:"images"`
	Scrubber       bool         `json:"scrubber,omitempty"`
	ScrubberAction string       `json:"scrubberAction,omitempty"`
	FlowTag        bool         `json:"flowTag,omitempty"`
	FlowTagText    string       `json:"flowTagText,omitempty"`
	IgnoreStale    bool         `json:"ignoreStaleMessages,omitempty"`
	ValidateCoT    bool         `json:"validateXml,omitempty"`
	ValidateUID    bool         `json:"validateClientUid,omitempty"`
}

func isOwnSA(e *cot.Event) bool {
	if !strings.HasPrefix(e.Type, "a-") || e.Detail == nil {
		return false
	}
	if e.Detail.Child("takv") != nil {
		return true
	}
	c := e.Detail.Child("contact")
	return c != nil && c.Attr("endpoint") != "" && e.Detail.Child("__group") != nil
}

func (s *Server) enrolledUID(c *Client) string {
	c.enrollOnce.Do(func() {
		id := c.Identity()
		if id == nil || id.Cert == nil {
			return
		}
		u, ok := s.dir.User(id.Name)
		if !ok {
			return
		}
		serial := pki.SerialHex(id.Cert)
		for _, r := range u.Certs {
			if strings.EqualFold(r.Serial, serial) {
				c.enrollUID = r.ClientUID
			}
		}
	})
	return c.enrollUID
}

func validCoT(e *cot.Event) bool {
	if e.Version == "" || e.UID == "" || e.Type == "" || e.How == "" || e.Time.IsZero() || e.Start.IsZero() || e.Stale.IsZero() {
		return false
	}
	for _, r := range e.Type {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.;:/ ", r)) {
			return false
		}
	}
	p := e.Point
	if math.IsNaN(p.Lat) || math.IsNaN(p.Lon) || math.IsNaN(p.Hae) || math.IsNaN(p.Ce) || math.IsNaN(p.Le) {
		return false
	}
	return p.Lat >= -90 && p.Lat <= 90 && p.Lon >= -180 && p.Lon <= 180 && p.Ce >= 0 && p.Le >= 0
}

func parseArea(v string) (*geoFilter, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	parts := strings.Split(v, ",")
	if len(parts) != 4 {
		return nil, errors.New("area must be south latitude, west longitude, north latitude, east longitude")
	}
	var f [4]float64
	for i, p := range parts {
		x, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return nil, errors.New("area must contain four numbers")
		}
		f[i] = x
	}
	if f[0] < -90 || f[2] > 90 || f[0] >= f[2] || f[1] < -180 || f[3] > 180 || f[1] >= f[3] {
		return nil, errors.New("area corners are out of range or in the wrong order")
	}
	return &geoFilter{boxes: []bbox{{minLat: f[0], minLon: f[1], maxLat: f[2], maxLon: f[3]}}}, nil
}

func (s *Server) applyLinkArea(c *Client, area string) {
	g, err := parseArea(area)
	if err != nil {
		s.log.Warn("server link area ignored", "link", c.Name, "err", err)
		return
	}
	if g != nil {
		c.geo.Store(g)
		c.inArea = g
	}
}

func typeMatches(t string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(t, strings.TrimSuffix(p, "*")) {
				return true
			}
		} else if t == p {
			return true
		}
	}
	return false
}

func (s *Server) messageFilter(m *Message) bool {
	if m == nil || m.Event == nil || m.Source == nil || m.Source.Kind == KindCluster {
		return true
	}
	if !s.runInterceptors(m) {
		return false
	}
	e := m.Event
	if g := m.Source.inArea; g != nil && !g.passes(m) {
		return false
	}
	f := s.Config().Filters
	if f.IgnoreStale && !e.IsControl() && !e.IsDelete() && !e.Stale.IsZero() && e.Stale.Before(time.Now()) {
		return false
	}
	if f.ValidateCoT && !e.IsControl() && !validCoT(e) {
		return false
	}
	if f.ValidateUID && !m.Source.Relay && isOwnSA(e) {
		if want := s.enrolledUID(m.Source); want != "" && want != e.UID {
			s.log.Warn("connection closed: position report with a uid that does not match the certificate's enrollment", "user", m.Source.User(), "uid", e.UID, "enrolled", want, "remote", m.Source.Remote)
			m.Source.Close()
			return false
		}
	}
	if len(f.DropTypes) > 0 && !e.IsControl() && !e.IsDelete() && typeMatches(e.Type, f.DropTypes) {
		return false
	}
	if len(f.DropRules) > 0 && s.dropByRules(m, f.DropRules) {
		return false
	}
	if f.Scrubber && !scrubEvent(e, f.ScrubberAction) {
		return false
	}
	if (f.Images.Thumbnail || f.Images.URLAdd) && e.Detail != nil {
		s.processImages(e, f.Images)
	}
	if f.FlowTag && !e.IsControl() {
		e.AddFlowTag(firstNonEmpty(f.FlowTagText, s.Config().Name), time.Now())
	}
	if len(f.StripDetails) > 0 && e.Detail != nil {
		for _, name := range f.StripDetails {
			if name = strings.TrimSpace(name); name != "" {
				e.Detail.RemoveAll(name)
			}
		}
	}
	return true
}
