package server

import (
	"errors"
	"strconv"
	"strings"
)

type MessageFilters struct {
	DropTypes    []string `json:"dropTypes,omitempty"`
	StripDetails []string `json:"stripDetails,omitempty"`
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
	if m == nil || m.Event == nil || m.Source == nil {
		return true
	}
	e := m.Event
	if g := m.Source.inArea; g != nil && !g.passes(m) {
		return false
	}
	f := s.Config().Filters
	if len(f.DropTypes) > 0 && !e.IsControl() && !e.IsDelete() && typeMatches(e.Type, f.DropTypes) {
		return false
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
