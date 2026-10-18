package server

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

var errNoFederate = errors.New("no such federate")

func (s *Server) federateRecord(id string) (FederateConfig, bool) {
	cfg := s.Config().Federation
	if f, ok := cfg.federate(id, id); ok {
		return f, true
	}
	if s.fedSeen != nil {
		if v, ok := s.fedSeen.Get(id); ok {
			return FederateConfig{ID: v.ID, Name: v.Name}, true
		}
		for _, v := range s.fedSeen.All() {
			if normFingerprint(v.ID) == normFingerprint(id) || strings.EqualFold(v.Name, id) {
				return FederateConfig{ID: v.ID, Name: v.Name}, true
			}
		}
	}
	return FederateConfig{}, false
}

func (s *Server) updateFederate(id string, fn func(f *FederateConfig) error) (FederateConfig, error) {
	base, ok := s.federateRecord(id)
	if !ok {
		base = FederateConfig{ID: id, Name: id}
	}
	var out FederateConfig
	_, err := s.UpdateConfig(func(c *Config) error {
		for i := range c.Federation.Federates {
			f := &c.Federation.Federates[i]
			if f.ID == base.ID || (base.ID != "" && normFingerprint(f.ID) == normFingerprint(base.ID)) || (f.ID == "" && strings.EqualFold(f.Name, base.Name)) {
				if err := fn(f); err != nil {
					return err
				}
				out = *f
				return nil
			}
		}
		f := base
		if err := fn(&f); err != nil {
			return err
		}
		c.Federation.Federates = append(c.Federation.Federates, f)
		out = f
		return nil
	})
	return out, err
}

func federateJSON(f FederateConfig) map[string]any {
	in, out := f.InboundGroups, f.OutboundGroups
	if in == nil {
		in = []string{}
	}
	if out == nil {
		out = []string{}
	}
	var mapping []string
	for remote, locals := range f.GroupMap {
		for _, l := range locals {
			mapping = append(mapping, remote+":"+l)
		}
	}
	sort.Strings(mapping)
	if mapping == nil {
		mapping = []string{}
	}
	hops := []map[string]any{}
	for g, n := range f.GroupHopLimits {
		hops = append(hops, map[string]any{"groupName": g, "hopLimit": n})
	}
	missions := []map[string]any{}
	for name, on := range f.Missions {
		missions = append(missions, map[string]any{"name": name, "enabled": on})
	}
	missionDefault := true
	if f.MissionsDefault != nil {
		missionDefault = *f.MissionsDefault
	}
	return map[string]any{
		"id": f.ID, "name": f.Name, "notes": f.Notes, "shareAlerts": !f.NoAlerts, "archive": !f.NoArchive, "federatedGroupMapping": len(f.GroupMap) > 0,
		"automaticGroupMapping": f.AutoGroupMap, "maxHops": f.MaxHops, "useGroupHopLimiting": f.UseGroupHops, "fallbackWhenNoGroupMappings": f.FallbackNoMap,
		"tokenFederate": f.TokenFederate, "tokenExpiration": f.TokenExpiration, "inboundGroup": in, "outboundGroup": out, "inboundGroupMapping": mapping,
		"outboundGroupHopLimit": hops, "missionFederateDefault": missionDefault, "mission": missions, "enabled": !f.Disabled,
	}
}

func (s *Server) allFederates() []FederateConfig {
	seen := map[string]bool{}
	var out []FederateConfig
	for _, f := range s.Config().Federation.Federates {
		out = append(out, f)
		seen[normFingerprint(f.ID)] = true
		seen[strings.ToLower(f.Name)] = true
	}
	if s.fedSeen != nil {
		for _, v := range s.fedSeen.All() {
			if seen[normFingerprint(v.ID)] || seen[strings.ToLower(v.Name)] {
				continue
			}
			out = append(out, FederateConfig{ID: v.ID, Name: v.Name})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) fedFederates(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, f := range s.allFederates() {
		out = append(out, federateJSON(f))
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Federation$Federate", out))
}

func (s *Server) fedDetails(w http.ResponseWriter, r *http.Request) {
	f, ok := s.federateRecord(firstNonEmpty(r.PathValue("id"), r.PathValue("federateId")))
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", errNoFederate.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Federation$Federate", federateJSON(f)))
}

func (s *Server) fedDetailsUpdate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID                    string   `json:"id"`
		Name                  *string  `json:"name"`
		Notes                 *string  `json:"notes"`
		ShareAlerts           *bool    `json:"shareAlerts"`
		Archive               *bool    `json:"archive"`
		AutomaticGroupMapping *bool    `json:"automaticGroupMapping"`
		FederatedGroupMapping *bool    `json:"federatedGroupMapping"`
		MaxHops               *int     `json:"maxHops"`
		UseGroupHopLimiting   *bool    `json:"useGroupHopLimiting"`
		Fallback              *bool    `json:"fallbackWhenNoGroupMappings"`
		Enabled               *bool    `json:"enabled"`
		InboundGroup          []string `json:"inboundGroup"`
		OutboundGroup         []string `json:"outboundGroup"`
		MissionDefault        *bool    `json:"missionFederateDefault"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil || b.ID == "" {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a federate with an id"))
		return
	}
	f, err := s.updateFederate(b.ID, func(f *FederateConfig) error {
		if b.Name != nil {
			f.Name = *b.Name
		}
		if b.Notes != nil {
			f.Notes = *b.Notes
		}
		if b.ShareAlerts != nil {
			f.NoAlerts = !*b.ShareAlerts
		}
		if b.Archive != nil {
			f.NoArchive = !*b.Archive
		}
		if b.AutomaticGroupMapping != nil {
			f.AutoGroupMap = *b.AutomaticGroupMapping
		}
		if b.FederatedGroupMapping != nil && !*b.FederatedGroupMapping {
			f.GroupMap = nil
		}
		if b.MaxHops != nil {
			f.MaxHops = *b.MaxHops
		}
		if b.UseGroupHopLimiting != nil {
			f.UseGroupHops = *b.UseGroupHopLimiting
		}
		if b.Fallback != nil {
			f.FallbackNoMap = *b.Fallback
		}
		if b.Enabled != nil {
			f.Disabled = !*b.Enabled
		}
		if b.InboundGroup != nil {
			f.InboundGroups = b.InboundGroup
		}
		if b.OutboundGroup != nil {
			f.OutboundGroups = b.OutboundGroup
		}
		if b.MissionDefault != nil {
			v := *b.MissionDefault
			f.MissionsDefault = &v
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Federation$Federate", federateJSON(f)))
}

func (s *Server) fedDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("federateId")
	f, ok := s.federateRecord(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", errNoFederate.Error()))
		return
	}
	s.UpdateConfig(func(c *Config) error {
		c.Federation.Federates = slices.DeleteFunc(c.Federation.Federates, func(x FederateConfig) bool {
			return x.ID == f.ID || (x.ID == "" && x.Name == f.Name)
		})
		return nil
	})
	if s.fedSeen != nil {
		s.fedSeen.Delete(f.ID)
	}
	w.WriteHeader(http.StatusOK)
}

func directionValue(v string) (in, out bool) {
	switch strings.ToUpper(v) {
	case "IN", "INBOUND":
		return true, false
	case "OUT", "OUTBOUND":
		return false, true
	}
	return true, true
}

func groupAssoc(id, idKey string, in, out []string) []map[string]any {
	list := []map[string]any{}
	for _, g := range in {
		list = append(list, map[string]any{idKey: id, "group": g, "direction": "INBOUND"})
	}
	for _, g := range out {
		list = append(list, map[string]any{idKey: id, "group": g, "direction": "OUTBOUND"})
	}
	return list
}

func (s *Server) fedGroupsGet(w http.ResponseWriter, r *http.Request) {
	f, _ := s.federateRecord(r.PathValue("federateId"))
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.FederateGroupAssociation", groupAssoc(firstNonEmpty(f.ID, r.PathValue("federateId")), "federateId", f.InboundGroups, f.OutboundGroups)))
}

func addUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(slices.Clone(list), v)
}

func removeValue(list []string, v string) []string {
	return slices.DeleteFunc(slices.Clone(list), func(x string) bool { return x == v })
}

func (s *Server) fedGroupsAdd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		FederateID string `json:"federateId"`
		Group      string `json:"group"`
		Direction  string `json:"direction"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil || b.FederateID == "" || !validGroup.MatchString(b.Group) {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected federateId, group and direction"))
		return
	}
	s.dir.EnsureGroup(b.Group, "Federation", false)
	in, out := directionValue(b.Direction)
	f, err := s.updateFederate(b.FederateID, func(f *FederateConfig) error {
		if in {
			f.InboundGroups = addUnique(f.InboundGroups, b.Group)
		}
		if out {
			f.OutboundGroups = addUnique(f.OutboundGroups, b.Group)
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.FederateGroupAssociation", groupAssoc(f.ID, "federateId", f.InboundGroups, f.OutboundGroups)))
}

func (s *Server) fedGroupsRemove(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in, out := directionValue(q.Get("direction"))
	_, err := s.updateFederate(r.PathValue("federateId"), func(f *FederateConfig) error {
		if in {
			f.InboundGroups = removeValue(f.InboundGroups, q.Get("group"))
		}
		if out {
			f.OutboundGroups = removeValue(f.OutboundGroups, q.Get("group"))
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) fedGroupMap(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := r.PathValue("federateId")
	if r.Method != http.MethodGet {
		remote, local := q.Get("remoteGroup"), q.Get("localGroup")
		if remote == "" || (r.Method == http.MethodPost && !validGroup.MatchString(local)) {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "remoteGroup and localGroup are required"))
			return
		}
		if r.Method == http.MethodPost {
			s.dir.EnsureGroup(local, "Federation", false)
		}
		_, err := s.updateFederate(id, func(f *FederateConfig) error {
			if f.GroupMap == nil {
				f.GroupMap = map[string][]string{}
			}
			if r.Method == http.MethodPost {
				f.GroupMap[remote] = addUnique(f.GroupMap[remote], local)
			} else if local == "" {
				delete(f.GroupMap, remote)
			} else if f.GroupMap[remote] = removeValue(f.GroupMap[remote], local); len(f.GroupMap[remote]) == 0 {
				delete(f.GroupMap, remote)
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
	}
	f, _ := s.federateRecord(id)
	m := f.GroupMap
	if m == nil {
		m = map[string][]string{}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.util.Map", m))
}

func (s *Server) fedHopLimits(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("federateId")
	switch r.Method {
	case http.MethodPost:
		var raw map[string]any
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&raw); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a group and hop limit"))
			return
		}
		limits := map[string]int{}
		if g, ok := raw["groupName"].(string); ok {
			n, _ := raw["hopLimit"].(float64)
			limits[g] = int(n)
		} else if g, ok := raw["group"].(string); ok {
			n, _ := raw["hopLimit"].(float64)
			limits[g] = int(n)
		} else {
			for g, v := range raw {
				if n, ok := v.(float64); ok {
					limits[g] = int(n)
				}
			}
		}
		_, err := s.updateFederate(id, func(f *FederateConfig) error {
			if f.GroupHopLimits == nil {
				f.GroupHopLimits = map[string]int{}
			}
			for g, n := range limits {
				f.GroupHopLimits[g] = n
			}
			f.UseGroupHops = true
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
	case http.MethodDelete:
		g := r.URL.Query().Get("group")
		s.updateFederate(id, func(f *FederateConfig) error {
			delete(f.GroupHopLimits, g)
			return nil
		})
	}
	f, _ := s.federateRecord(id)
	out := []map[string]any{}
	for g, n := range f.GroupHopLimits {
		out = append(out, map[string]any{"groupName": g, "hopLimit": n})
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Federation$Federate$OutboundGroupHopLimit", out))
}

func (s *Server) fedRemoteGroups(w http.ResponseWriter, r *http.Request) {
	groups := []string{}
	if f, ok := s.federateRecord(r.PathValue("federateId")); ok && s.fedSeen != nil {
		if v, ok := s.fedSeen.Get(f.ID); ok && v.RemoteGroups != nil {
			groups = v.RemoteGroups
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", groups))
}

func (s *Server) fedContacts(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("federateId")
	f, _ := s.federateRecord(id)
	out := []map[string]any{}
	for _, fc := range s.fed.clients() {
		p := fc.c.fed
		if p == nil || !(p.id == normFingerprint(id) || p.id == normFingerprint(f.ID) || strings.EqualFold(p.name, id) || strings.EqualFold(p.name, f.Name)) {
			continue
		}
		fc.c.mu.Lock()
		for uid, cs := range fc.c.remote {
			out = append(out, map[string]any{"uid": uid, "callsign": cs, "federateId": firstNonEmpty(f.ID, id)})
		}
		fc.c.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.RemoteContact", out))
}

func (s *Server) fedMissions(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Default  *bool `json:"missionFederateDefault"`
		Missions []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"missions"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected mission federation settings"))
		return
	}
	f, err := s.updateFederate(r.PathValue("federateId"), func(f *FederateConfig) error {
		if b.Default != nil {
			v := *b.Default
			f.MissionsDefault = &v
		}
		f.Missions = map[string]bool{}
		for _, m := range b.Missions {
			f.Missions[m.Name] = m.Enabled
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Federation$Federate", federateJSON(f)))
}

func (s *Server) updateFederateCA(fp string, fn func(ca *FederateCAConfig)) error {
	fp = normFingerprint(fp)
	if fp == "" {
		return errors.New("caId is required")
	}
	_, err := s.UpdateConfig(func(c *Config) error {
		for i := range c.Federation.CAs {
			if normFingerprint(c.Federation.CAs[i].Fingerprint) == fp {
				ca := c.Federation.CAs[i]
				ca.InboundGroups, ca.OutboundGroups = slices.Clone(ca.InboundGroups), slices.Clone(ca.OutboundGroups)
				fn(&ca)
				c.Federation.CAs[i] = ca
				return nil
			}
		}
		ca := FederateCAConfig{Fingerprint: fp}
		fn(&ca)
		c.Federation.CAs = append(c.Federation.CAs, ca)
		return nil
	})
	return err
}

func (s *Server) fedCAGroupsGet(w http.ResponseWriter, r *http.Request) {
	ca, _ := s.Config().Federation.federateCA(r.PathValue("caId"))
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.FederateCAGroupAssociation", groupAssoc(r.PathValue("caId"), "caId", ca.InboundGroups, ca.OutboundGroups)))
}

func (s *Server) fedCAGroupsAdd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		CAID      string `json:"caId"`
		Group     string `json:"group"`
		Direction string `json:"direction"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil || !validGroup.MatchString(b.Group) {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected caId, group and direction"))
		return
	}
	s.dir.EnsureGroup(b.Group, "Federation", false)
	in, out := directionValue(b.Direction)
	if err := s.updateFederateCA(b.CAID, func(ca *FederateCAConfig) {
		if in {
			ca.InboundGroups = addUnique(ca.InboundGroups, b.Group)
		}
		if out {
			ca.OutboundGroups = addUnique(ca.OutboundGroups, b.Group)
		}
	}); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) fedCAGroupsRemove(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in, out := directionValue(q.Get("direction"))
	s.updateFederateCA(r.PathValue("caId"), func(ca *FederateCAConfig) {
		if in {
			ca.InboundGroups = removeValue(ca.InboundGroups, q.Get("group"))
		}
		if out {
			ca.OutboundGroups = removeValue(ca.OutboundGroups, q.Get("group"))
		}
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) fedCAHops(w http.ResponseWriter, r *http.Request) {
	var b struct {
		CAID    string `json:"caId"`
		MaxHops int    `json:"maxHops"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected caId and maxHops"))
		return
	}
	if err := s.updateFederateCA(b.CAID, func(ca *FederateCAConfig) { ca.MaxHops = b.MaxHops }); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) fedCATokenAuth(w http.ResponseWriter, r *http.Request) {
	var b map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected caId and allowTokenAuth"))
		return
	}
	id, _ := b["caId"].(string)
	allow, _ := b["allowTokenAuth"].(bool)
	days := 0
	if d, ok := b["tokenAuthDuration"].(float64); ok && d > 0 {
		days = int(d)
		if d > 1e6 {
			days = int(d / 86400000)
		}
	}
	if err := s.updateFederateCA(id, func(ca *FederateCAConfig) { ca.AllowTokenAuth, ca.TokenAuthDays = allow, days }); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) trustedFederationCAs() []*x509.Certificate {
	var out []*x509.Certificate
	for _, entry := range s.Config().Federation.TrustPEM {
		if certs, err := pki.ParseCertPEM([]byte(entry)); err == nil {
			out = append(out, certs...)
		}
	}
	return out
}

func (s *Server) fedCertificates(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	cfg := s.Config().Federation
	for _, c := range s.trustedFederationCAs() {
		fp := certFingerprint(c)
		ca, _ := cfg.federateCA(fp)
		out = append(out, map[string]any{"fingerprint": colonFingerprint(fp), "subjectDn": c.Subject.String(), "issuerDn": c.Issuer.String(), "serialNumber": c.SerialNumber.String(),
			"notBefore": isoTime(c.NotBefore), "notAfter": isoTime(c.NotAfter), "maxHops": ca.MaxHops, "allowTokenAuth": ca.AllowTokenAuth, "tokenAuthDuration": ca.TokenAuthDays})
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.FederationApi.CertificateSummary", out))
}

func (s *Server) fedCertificateAdd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var data []byte
	if f, _, err := r.FormFile("file"); err == nil {
		data, _ = io.ReadAll(f)
		f.Close()
	} else {
		data, _ = io.ReadAll(r.Body)
	}
	certs, err := pki.ParseCertPEM(data)
	if err != nil || len(certs) == 0 {
		if c, derr := x509.ParseCertificate(data); derr == nil {
			certs = []*x509.Certificate{c}
		} else {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "upload a PEM or DER certificate"))
			return
		}
	}
	var added []string
	_, err = s.UpdateConfig(func(c *Config) error {
		have := map[string]bool{}
		for _, existing := range s.trustedFederationCAs() {
			have[certFingerprint(existing)] = true
		}
		for _, cert := range certs {
			fp := certFingerprint(cert)
			if have[fp] {
				continue
			}
			c.Federation.TrustPEM = append(c.Federation.TrustPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
			added = append(added, colonFingerprint(fp))
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", added))
}

func (s *Server) fedCertificateDelete(w http.ResponseWriter, r *http.Request) {
	fp := normFingerprint(r.PathValue("fingerprint"))
	removed := false
	s.UpdateConfig(func(c *Config) error {
		var keep []string
		for _, entry := range c.Federation.TrustPEM {
			certs, err := pki.ParseCertPEM([]byte(entry))
			if err == nil && len(certs) == 1 && certFingerprint(certs[0]) == fp {
				removed = true
				continue
			}
			keep = append(keep, entry)
		}
		c.Federation.TrustPEM = keep
		c.Federation.CAs = slices.DeleteFunc(c.Federation.CAs, func(ca FederateCAConfig) bool { return normFingerprint(ca.Fingerprint) == fp })
		return nil
	})
	if !removed {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no trusted certificate with that fingerprint"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func isFedURL(raw string) (int, bool) {
	switch {
	case strings.HasPrefix(raw, "fed2://"):
		return 2, true
	case strings.HasPrefix(raw, "fed://"):
		return 1, true
	}
	return 0, false
}

func (s *Server) outgoingJSON(p PeerConfig, st *PeerStatus) map[string]any {
	ver, _ := isFedURL(p.URL)
	u, _ := url.Parse(p.URL)
	host, port := "", 0
	if u != nil {
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
	}
	if port == 0 {
		port = map[int]int{1: 9000, 2: 9001}[ver]
	}
	oc := map[string]any{"displayName": p.Name, "address": host, "port": port, "enabled": p.Enabled, "protocolVersion": ver, "reconnectInterval": 30,
		"maxRetries": 0, "unlimitedRetries": true, "useToken": p.Token != "", "tokenType": map[bool]string{true: "auto", false: ""}[p.Token == "auto"], "tls": true}
	status := "DISABLED"
	if p.Enabled {
		status = "CONNECTING"
	}
	summary := map[string]any{"connectionStatusValue": status}
	if st != nil {
		switch st.State {
		case "connected":
			summary["connectionStatusValue"] = "CONNECTED"
		case "error", "retrying":
			summary["connectionStatusValue"] = "RETRY_SCHEDULED"
			summary["lastError"] = st.Error
		}
		summary["messagesReceived"], summary["messagesSent"] = st.Rx, st.Tx
	}
	return map[string]any{"outgoingConnection": oc, "connectionInfoSummary": summary}
}

func (s *Server) fedOutgoingList(w http.ResponseWriter, r *http.Request) {
	status := map[string]*PeerStatus{}
	sts := s.peerStatus()
	for i := range sts {
		status[sts[i].Name] = &sts[i]
	}
	out := []map[string]any{}
	for _, p := range s.Config().Peers {
		if _, ok := isFedURL(p.URL); ok {
			out = append(out, s.outgoingJSON(p, status[p.Name]))
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.OutgoingConnectionSummary", out))
}

func (s *Server) fedOutgoingFind(name string) (PeerConfig, bool) {
	for _, p := range s.Config().Peers {
		if _, ok := isFedURL(p.URL); ok && p.Name == name {
			return p, true
		}
	}
	return PeerConfig{}, false
}

func (s *Server) fedOutgoingGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.fedOutgoingFind(r.PathValue("name"))
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no outgoing connection with that name"))
		return
	}
	var st *PeerStatus
	for _, x := range s.peerStatus() {
		if x.Name == p.Name {
			x := x
			st = &x
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.OutgoingConnectionSummary", s.outgoingJSON(p, st)))
}

type fedOutgoingBody struct {
	DisplayName     string `json:"displayName"`
	Name            string `json:"name"`
	Address         string `json:"address"`
	Port            int    `json:"port"`
	Enabled         *bool  `json:"enabled"`
	ProtocolVersion int    `json:"protocolVersion"`
	ConnectionToken string `json:"connectionToken"`
	UseToken        *bool  `json:"useToken"`
	TokenType       string `json:"tokenType"`
}

func (b fedOutgoingBody) apply(p *PeerConfig) error {
	if n := firstNonEmpty(b.DisplayName, b.Name); n != "" {
		p.Name = n
	}
	ver, _ := isFedURL(p.URL)
	if b.ProtocolVersion != 0 {
		ver = b.ProtocolVersion
	}
	if ver != 1 {
		ver = 2
	}
	u, _ := url.Parse(p.URL)
	host, port := b.Address, b.Port
	if u != nil {
		if host == "" {
			host = u.Hostname()
		}
		if port == 0 {
			port, _ = strconv.Atoi(u.Port())
		}
	}
	if host == "" {
		return errors.New("address is required")
	}
	if port == 0 {
		port = map[int]int{1: 9000, 2: 9001}[ver]
	}
	scheme := "fed2"
	if ver == 1 {
		scheme = "fed"
	}
	p.URL = scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	if b.Enabled != nil {
		p.Enabled = *b.Enabled
	}
	if b.UseToken != nil && !*b.UseToken {
		p.Token = ""
	}
	if b.ConnectionToken != "" {
		p.Token = b.ConnectionToken
	} else if strings.EqualFold(b.TokenType, "auto") || (b.UseToken != nil && *b.UseToken && p.Token == "") {
		p.Token = "auto"
	}
	if p.Direction == "" {
		p.Direction = "both"
	}
	return nil
}

func (s *Server) fedOutgoingSave(w http.ResponseWriter, r *http.Request) {
	var b fedOutgoingBody
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected an outgoing connection"))
		return
	}
	name := firstNonEmpty(b.DisplayName, b.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "displayName is required"))
		return
	}
	var saved PeerConfig
	_, err := s.UpdateConfig(func(c *Config) error {
		for i := range c.Peers {
			if c.Peers[i].Name == name {
				if r.Method == http.MethodPost {
					return fmt.Errorf("a link named %s already exists", name)
				}
				if err := b.apply(&c.Peers[i]); err != nil {
					return err
				}
				saved = c.Peers[i]
				return nil
			}
		}
		if r.Method == http.MethodPut {
			return errors.New("no outgoing connection with that name")
		}
		p := PeerConfig{Name: name, Enabled: true, Direction: "both"}
		if err := b.apply(&p); err != nil {
			return err
		}
		c.Peers = append(c.Peers, p)
		saved = p
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	s.reloadPeers()
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.network.OutgoingConnectionSummary", s.outgoingJSON(saved, nil)))
}

func (s *Server) fedOutgoingDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.fedOutgoingFind(name); !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no outgoing connection with that name"))
		return
	}
	s.UpdateConfig(func(c *Config) error {
		c.Peers = slices.DeleteFunc(slices.Clone(c.Peers), func(p PeerConfig) bool { return p.Name == name })
		return nil
	})
	s.reloadPeers()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) fedOutgoingStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.fedOutgoingFind(name); !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no outgoing connection with that name"))
		return
	}
	if r.Method == http.MethodPost {
		on := strings.EqualFold(r.URL.Query().Get("newStatus"), "true")
		s.UpdateConfig(func(c *Config) error {
			for i := range c.Peers {
				if c.Peers[i].Name == name {
					c.Peers[i].Enabled = on
				}
			}
			return nil
		})
		s.reloadPeers()
	}
	state := "DISABLED"
	for _, st := range s.peerStatus() {
		if st.Name == name {
			state = strings.ToUpper(firstNonEmpty(st.State, "connecting"))
		}
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", state))
}

func (s *Server) fedNum(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Integer", len(s.fed.clients())))
}

func (s *Server) fedClearEvents(w http.ResponseWriter, r *http.Request) {
	if s.fedSeen != nil {
		for _, v := range s.fedSeen.All() {
			v.LastDisconnected = v.LastDisconnected.AddDate(-100, 0, 0)
			s.fedSeen.Put(v.ID, v)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) fedCADownloadEnabled(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", s.Config().Federation.CADownload))
}

func (s *Server) fedCADownload(w http.ResponseWriter, r *http.Request) {
	if !s.Config().Federation.CADownload {
		writeJSON(w, http.StatusForbidden, s.envelope("error", "CA download is disabled"))
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFileName(s.Config().Name)+`-ca.pem"`)
	w.Write(s.pki.CA.CertPEM)
}

func (s *Server) fedConfigJSON() map[string]any {
	cfg := s.Config()
	f := cfg.Federation
	missions := []map[string]any{}
	for name, secs := range f.Disruption.Missions {
		missions = append(missions, map[string]any{"name": name, "interval": secs})
	}
	exts := f.FileFilter.Extensions
	if len(exts) == 0 {
		exts = []string{"pref"}
	}
	tokenPort := f.Token.Port
	if tokenPort <= 0 {
		tokenPort = 9002
	}
	return map[string]any{
		"enabled": f.Enabled, "serverPortEnabled": cfg.Ports.Federation > 0, "serverPortv1": cfg.Ports.Federation, "serverPortEnabledv2": cfg.Ports.FederationV2 > 0,
		"serverPortv2": cfg.Ports.FederationV2, "tlsVersion": "TLSv1.2", "webBaseURL": "", "allowMissionFederation": !f.NoMissions, "allowDataFeedFederation": !f.NoDataFeeds,
		"allowFederatedDelete": f.AllowDelete, "enableMissionFederationDisruptionTolerance": f.Disruption.Enabled,
		"missionFederationDisruptionToleranceRecencySeconds": f.Disruption.RecencySeconds, "missionInterval": missions, "coreVersion": 2,
		"enableDataPackageAndMissionFileFilter": f.FileFilter.Enabled, "fileExtension": exts, "maxHops": f.MaxHops, "caDownloadEnabled": f.CADownload,
		"federationTokenAuthentication": []map[string]any{{"enabled": f.Token.Enabled, "port": tokenPort}},
	}
}

func (s *Server) fedConfigGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.FederationConfigInfo", s.fedConfigJSON()))
}

func (s *Server) fedConfigPut(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Enabled         *bool    `json:"enabled"`
		PortV1Enabled   *bool    `json:"serverPortEnabled"`
		PortV1          *int     `json:"serverPortv1"`
		PortV2Enabled   *bool    `json:"serverPortEnabledv2"`
		PortV2          *int     `json:"serverPortv2"`
		Missions        *bool    `json:"allowMissionFederation"`
		DataFeeds       *bool    `json:"allowDataFeedFederation"`
		Delete          *bool    `json:"allowFederatedDelete"`
		Disruption      *bool    `json:"enableMissionFederationDisruptionTolerance"`
		Recency         *int     `json:"missionFederationDisruptionToleranceRecencySeconds"`
		FileFilter      *bool    `json:"enableDataPackageAndMissionFileFilter"`
		Extensions      []string `json:"fileExtension"`
		MaxHops         *int     `json:"maxHops"`
		CADownload      *bool    `json:"caDownloadEnabled"`
		MissionInterval []struct {
			Name     string `json:"name"`
			Interval int    `json:"interval"`
		} `json:"missionInterval"`
		Token []struct {
			Enabled bool `json:"enabled"`
			Port    int  `json:"port"`
		} `json:"federationTokenAuthentication"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a federation configuration"))
		return
	}
	before := s.Config()
	next, err := s.UpdateConfig(func(c *Config) error {
		f := &c.Federation
		if b.Enabled != nil {
			f.Enabled = *b.Enabled
		}
		if b.PortV1 != nil && (b.PortV1Enabled == nil || *b.PortV1Enabled) {
			c.Ports.Federation = *b.PortV1
		}
		if b.PortV1Enabled != nil && !*b.PortV1Enabled {
			c.Ports.Federation = 0
		}
		if b.PortV2 != nil && (b.PortV2Enabled == nil || *b.PortV2Enabled) {
			c.Ports.FederationV2 = *b.PortV2
		}
		if b.PortV2Enabled != nil && !*b.PortV2Enabled {
			c.Ports.FederationV2 = 0
		}
		if b.Missions != nil {
			f.NoMissions = !*b.Missions
		}
		if b.DataFeeds != nil {
			f.NoDataFeeds = !*b.DataFeeds
		}
		if b.Delete != nil {
			f.AllowDelete = *b.Delete
		}
		if b.Disruption != nil {
			f.Disruption.Enabled = *b.Disruption
		}
		if b.Recency != nil {
			f.Disruption.RecencySeconds = *b.Recency
		}
		if b.MissionInterval != nil {
			f.Disruption.Missions = map[string]int{}
			for _, m := range b.MissionInterval {
				f.Disruption.Missions[m.Name] = m.Interval
			}
		}
		if b.FileFilter != nil {
			f.FileFilter.Enabled = *b.FileFilter
		}
		if b.Extensions != nil {
			f.FileFilter.Extensions = b.Extensions
		}
		if b.MaxHops != nil && *b.MaxHops > 0 {
			f.MaxHops = *b.MaxHops
		}
		if b.CADownload != nil {
			f.CADownload = *b.CADownload
		}
		if len(b.Token) > 0 {
			f.Token.Enabled, f.Token.Port = b.Token[0].Enabled, b.Token[0].Port
		}
		return validateConfig(c)
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	restart := before.Federation.Enabled != next.Federation.Enabled || before.Ports != next.Ports || before.Federation.Token != next.Federation.Token
	out := s.fedConfigJSON()
	out["restartRequired"] = restart
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.FederationConfigInfo", out))
}

func (s *Server) fedConfigVerify(w http.ResponseWriter, r *http.Request) {
	n := len(s.trustedFederationCAs())
	writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", n > 0 || len(s.Config().Federation.TrustPEM) == 0))
}

func (s *Server) federationAPIRoutes(a func(string, http.HandlerFunc)) {
	a("GET /Marti/api/federates", s.fedFederates)
	a("GET /Marti/api/federatedetails/{id}", s.fedDetails)
	a("PUT /Marti/api/federatedetails", s.fedDetailsUpdate)
	a("DELETE /Marti/api/federatedetails/{federateId}", s.fedDelete)
	a("GET /Marti/api/federategroups/{federateId}", s.fedGroupsGet)
	a("POST /Marti/api/federategroups", s.fedGroupsAdd)
	a("DELETE /Marti/api/federategroups/{federateId}", s.fedGroupsRemove)
	a("POST /Marti/api/federategroupconfig", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	a("GET /Marti/api/federategroupsmap/{federateId}", s.fedGroupMap)
	a("POST /Marti/api/federategroupsmap/{federateId}", s.fedGroupMap)
	a("DELETE /Marti/api/federategroupsmap/{federateId}", s.fedGroupMap)
	a("GET /Marti/api/federate-outbound-groups-hop-limit/{federateId}", s.fedHopLimits)
	a("POST /Marti/api/federate-outbound-groups-hop-limit/{federateId}", s.fedHopLimits)
	a("DELETE /Marti/api/federate-outbound-groups-hop-limit/{federateId}", s.fedHopLimits)
	a("GET /Marti/api/federateremotegroups/{federateId}", s.fedRemoteGroups)
	a("GET /Marti/api/federatecontacts/{federateId}", s.fedContacts)
	a("PUT /Marti/api/federatemissions/{federateId}", s.fedMissions)
	a("GET /Marti/api/federatecagroups/{caId}", s.fedCAGroupsGet)
	a("POST /Marti/api/federatecagroups", s.fedCAGroupsAdd)
	a("DELETE /Marti/api/federatecagroups/{caId}", s.fedCAGroupsRemove)
	a("POST /Marti/api/federatecahops", s.fedCAHops)
	a("POST /Marti/api/federatecatokenauth", s.fedCATokenAuth)
	a("GET /Marti/api/federatecertificates", s.fedCertificates)
	a("POST /Marti/api/federatecertificates", s.fedCertificateAdd)
	a("DELETE /Marti/api/federatecertificates/{fingerprint}", s.fedCertificateDelete)
	a("GET /Marti/api/outgoingconnections", s.fedOutgoingList)
	a("POST /Marti/api/outgoingconnections", s.fedOutgoingSave)
	a("PUT /Marti/api/outgoingconnections", s.fedOutgoingSave)
	a("GET /Marti/api/outgoingconnections/{name}", s.fedOutgoingGet)
	a("DELETE /Marti/api/outgoingconnections/{name}", s.fedOutgoingDelete)
	a("GET /Marti/api/outgoingconnectionstatus/{name}", s.fedOutgoingStatus)
	a("POST /Marti/api/outgoingconnectionstatus/{name}", s.fedOutgoingStatus)
	a("GET /Marti/api/fednum", s.fedNum)
	a("GET /Marti/api/clearFederationEvents", s.fedClearEvents)
	a("GET /Marti/api/cadownloadenabled", s.fedCADownloadEnabled)
	a("GET /Marti/api/federationconfig", s.fedConfigGet)
	a("PUT /Marti/api/federationconfig", s.fedConfigPut)
	a("GET /Marti/api/federationconfig/verify", s.fedConfigVerify)
}
