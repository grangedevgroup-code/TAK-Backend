package server

import (
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

func (s *Server) takAdminRoutes(m, a func(string, http.HandlerFunc)) {
	m("GET /Marti/api/inputs/storeForwardChat/enabled", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", s.Config().Retention.ChatDays > 0))
	})
	a("PUT /Marti/api/inputs/storeForwardChat/enable", func(w http.ResponseWriter, r *http.Request) { s.setStoreForward(w, true) })
	a("PUT /Marti/api/inputs/storeForwardChat/disable", func(w http.ResponseWriter, r *http.Request) { s.setStoreForward(w, false) })
	m("GET /Marti/api/subscription/{uid}", s.martiSubscriptionOne)
	a("POST /Marti/api/subscriptions/add", s.martiSubscriptionAdd)
	a("POST /Marti/api/subscriptions/incognito/{uid}", s.martiSubscriptionIncognito)
	a("PUT /Marti/api/subscriptions/{uid}/filter", s.martiSubscriptionFilterPut)
	a("DELETE /Marti/api/subscriptions/{a}/{b}", s.martiSubscriptionDelete)
}

func (s *Server) setStoreForward(w http.ResponseWriter, on bool) {
	cfg, err := s.UpdateConfig(func(c *Config) error {
		switch {
		case on && c.Retention.ChatDays <= 0:
			c.Retention.ChatDays = DefaultConfig().Retention.ChatDays
		case !on:
			c.Retention.ChatDays = 0
		}
		return nil
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", cfg.Retention.ChatDays > 0))
}

func (s *Server) clientByUID(uid string) *Client {
	if c := s.hub.ByUID(uid); c != nil {
		return c
	}
	for _, c := range s.hub.Clients() {
		if strconv.FormatUint(c.ID, 10) == uid {
			return c
		}
	}
	return nil
}

func (s *Server) martiSubscriptionOne(w http.ResponseWriter, r *http.Request) {
	c := s.clientByUID(r.PathValue("uid"))
	if c == nil || c.Relay || !s.visibleTo(identityOf(r), c.InMask()) {
		writeJSON(w, http.StatusNotFound, s.envelope("SubscriptionInfo", nil))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("SubscriptionInfo", s.subscriptionInfo(c)))
}

func (s *Server) martiSubscriptionIncognito(w http.ResponseWriter, r *http.Request) {
	c := s.clientByUID(r.PathValue("uid"))
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no connected client with that uid"})
		return
	}
	on := !c.incognito.Load()
	c.incognito.Store(on)
	s.log.Info("incognito changed", "client", r.PathValue("uid"), "incognito", on, "by", identityOf(r).Name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiSubscriptionFilterPut(w http.ResponseWriter, r *http.Request) {
	c := s.clientByUID(r.PathValue("uid"))
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no connected client with that uid"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	n, err := xmltree.Parse(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a filter XML document"})
		return
	}
	gf := n
	if n.Name != "geospatialFilter" {
		gf = n.Child("geospatialFilter")
	}
	if gf == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the filter has no geospatialFilter"})
		return
	}
	g := &geoFilter{allTAK: strings.EqualFold(gf.Attr("filterTAKClients"), "false")}
	for _, b := range gf.All("boundingBox") {
		g.boxes = append(g.boxes, bbox{minLat: parseF(b.Attr("minLatitude")), minLon: parseF(b.Attr("minLongitude")), maxLat: parseF(b.Attr("maxLatitude")), maxLon: parseF(b.Attr("maxLongitude"))})
	}
	if len(g.boxes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the filter has no boundingBox"})
		return
	}
	c.geo.Store(g)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) martiSubscriptionDelete(w http.ResponseWriter, r *http.Request) {
	a, b := r.PathValue("a"), r.PathValue("b")
	switch {
	case b == "filter":
		c := s.clientByUID(a)
		if c == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no connected client with that uid"})
			return
		}
		c.geo.Store(nil)
		w.WriteHeader(http.StatusOK)
	case a == "delete":
		if !s.requireAdmin(w, r) {
			return
		}
		removed := false
		s.UpdateConfig(func(c *Config) error {
			n := len(c.Peers)
			c.Peers = slices.DeleteFunc(c.Peers, func(p PeerConfig) bool { return p.Name == b })
			removed = len(c.Peers) != n
			return nil
		})
		if removed {
			s.reloadPeers()
		} else if c := s.clientByUID(b); c != nil {
			c.Close()
			removed = true
		}
		if !removed {
			writeJSON(w, http.StatusBadRequest, s.envelope("String", "Could not delete subscription with uid: "+b))
			return
		}
		writeJSON(w, http.StatusOK, s.envelope("String", "Successfully deleted subscription with uid: "+b))
	default:
		s.martiUnknown(w, r)
	}
}

func (s *Server) martiSubscriptionAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UID          string `json:"uid"`
		Protocol     string `json:"protocol"`
		Address      string `json:"subaddr"`
		Port         string `json:"subport"`
		FilterGroups string `json:"filterGroups"`
		XPath        string `json:"xpath"`
	}
	if err := readJSON(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	body.UID = strings.TrimSpace(body.UID)
	proto := strings.ToLower(strings.TrimSpace(body.Protocol))
	port, err := strconv.Atoi(strings.TrimSpace(body.Port))
	if body.UID == "" || body.Address == "" || err != nil || port < 1 || port > 65535 || (proto != "tcp" && proto != "udp" && proto != "stcp" && proto != "tls") {
		writeJSON(w, http.StatusBadRequest, s.envelope("SubscriptionInfo", nil))
		return
	}
	if strings.TrimSpace(body.XPath) != "" && strings.TrimSpace(body.XPath) != "*" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "xpath subscriptions are not supported; use Message filters or groups instead"})
		return
	}
	p := PeerConfig{Name: body.UID, URL: proto + "://" + net.JoinHostPort(strings.TrimSpace(body.Address), strconv.Itoa(port)), Enabled: true, Direction: "out", Groups: splitList(body.FilterGroups), NoPresence: true}
	_, err = s.UpdateConfig(func(c *Config) error {
		if slices.ContainsFunc(c.Peers, func(x PeerConfig) bool { return x.Name == p.Name }) {
			return errors.New("a subscription or link with that uid already exists")
		}
		c.Peers = append(c.Peers, p)
		return nil
	})
	if err != nil {
		apiError(w, http.StatusConflict, err)
		return
	}
	s.reloadPeers()
	writeJSON(w, http.StatusCreated, s.envelope("SubscriptionInfo", map[string]any{"uid": p.Name, "clientUid": p.Name, "to": proto + ":" + body.Address + ":" + strconv.Itoa(port), "protocol": proto, "groups": p.Groups}))
}
