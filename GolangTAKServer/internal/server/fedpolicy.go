package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

type FederateConfig struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Notes           string              `json:"notes,omitempty"`
	Disabled        bool                `json:"disabled,omitempty"`
	InboundGroups   []string            `json:"inboundGroups,omitempty"`
	OutboundGroups  []string            `json:"outboundGroups,omitempty"`
	GroupMap        map[string][]string `json:"groupMap,omitempty"`
	AutoGroupMap    bool                `json:"automaticGroupMapping,omitempty"`
	FallbackNoMap   bool                `json:"fallbackWhenNoGroupMappings,omitempty"`
	MaxHops         int                 `json:"maxHops,omitempty"`
	UseGroupHops    bool                `json:"useGroupHopLimiting,omitempty"`
	GroupHopLimits  map[string]int      `json:"groupHopLimits,omitempty"`
	NoAlerts        bool                `json:"noAlerts,omitempty"`
	NoArchive       bool                `json:"noArchive,omitempty"`
	Missions        map[string]bool     `json:"missions,omitempty"`
	MissionsDefault *bool               `json:"missionsDefault,omitempty"`
	TokenFederate   bool                `json:"tokenFederate,omitempty"`
	TokenExpiration int64               `json:"tokenExpiration,omitempty"`
}

type FederateCAConfig struct {
	Fingerprint    string   `json:"fingerprint"`
	Name           string   `json:"name,omitempty"`
	InboundGroups  []string `json:"inboundGroups,omitempty"`
	OutboundGroups []string `json:"outboundGroups,omitempty"`
	MaxHops        int      `json:"maxHops,omitempty"`
	AllowTokenAuth bool     `json:"allowTokenAuth,omitempty"`
	TokenAuthDays  int      `json:"tokenAuthDays,omitempty"`
}

type FedTokenConfig struct {
	Enabled             bool `json:"enabled"`
	Port                int  `json:"port,omitempty"`
	AllowWithoutTLSCert bool `json:"allowWithoutTlsCertificate,omitempty"`
}

type FedFileFilter struct {
	Enabled    bool     `json:"enabled"`
	Extensions []string `json:"extensions,omitempty"`
}

type FedDisruption struct {
	Enabled        bool           `json:"enabled"`
	RecencySeconds int            `json:"recencySeconds,omitempty"`
	Unlimited      bool           `json:"unlimited,omitempty"`
	Missions       map[string]int `json:"missions,omitempty"`
}

func cloneFederates(list []FederateConfig) []FederateConfig {
	out := make([]FederateConfig, len(list))
	for i, f := range list {
		f.InboundGroups = slices.Clone(f.InboundGroups)
		f.OutboundGroups = slices.Clone(f.OutboundGroups)
		f.GroupMap = maps.Clone(f.GroupMap)
		for k, v := range f.GroupMap {
			f.GroupMap[k] = slices.Clone(v)
		}
		f.GroupHopLimits = maps.Clone(f.GroupHopLimits)
		f.Missions = maps.Clone(f.Missions)
		out[i] = f
	}
	return out
}

func normFingerprint(fp string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(fp))
}

func certFingerprint(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func colonFingerprint(fp string) string {
	fp = strings.ToUpper(normFingerprint(fp))
	var b strings.Builder
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(fp[i:min(i+2, len(fp))])
	}
	return b.String()
}

func chainCAFingerprint(chains [][]*x509.Certificate) string {
	for _, ch := range chains {
		if len(ch) > 1 {
			return certFingerprint(ch[len(ch)-1])
		}
	}
	return ""
}

type fedPolicy struct {
	id        string
	name      string
	caFP      string
	in        []string
	out       []string
	groupMap  map[string][]string
	auto      bool
	fallback  bool
	maxHops   int
	hopLimits map[string]int
	noAlerts  bool
	noArchive bool
	missions  map[string]bool
	missionOn bool
	disabled  bool
}

func (c FederationConfig) federate(id, name string) (FederateConfig, bool) {
	id = normFingerprint(id)
	for _, f := range c.Federates {
		if (id != "" && normFingerprint(f.ID) == id) || (f.ID == name && name != "") {
			return f, true
		}
	}
	for _, f := range c.Federates {
		if name != "" && strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return FederateConfig{}, false
}

func (c FederationConfig) federateCA(fp string) (FederateCAConfig, bool) {
	fp = normFingerprint(fp)
	if fp == "" {
		return FederateCAConfig{}, false
	}
	for _, ca := range c.CAs {
		if normFingerprint(ca.Fingerprint) == fp {
			return ca, true
		}
	}
	return FederateCAConfig{}, false
}

func (s *Server) fedPolicyFor(id, name, caFP string, linkGroups []string) *fedPolicy {
	cfg := s.Config().Federation
	p := &fedPolicy{id: normFingerprint(id), name: name, caFP: normFingerprint(caFP), in: slices.Clone(cfg.Groups), out: slices.Clone(cfg.Groups), maxHops: cfg.MaxHops, missionOn: true}
	if len(linkGroups) > 0 {
		p.in, p.out = slices.Clone(linkGroups), slices.Clone(linkGroups)
	}
	if ca, ok := cfg.federateCA(caFP); ok {
		if len(ca.InboundGroups) > 0 {
			p.in = slices.Clone(ca.InboundGroups)
		}
		if len(ca.OutboundGroups) > 0 {
			p.out = slices.Clone(ca.OutboundGroups)
		}
		if ca.MaxHops > 0 {
			p.maxHops = ca.MaxHops
		}
	}
	if f, ok := cfg.federate(id, name); ok {
		if f.ID == "" {
			f.ID = id
		}
		if len(f.InboundGroups) > 0 {
			p.in = slices.Clone(f.InboundGroups)
		}
		if len(f.OutboundGroups) > 0 {
			p.out = slices.Clone(f.OutboundGroups)
		}
		p.groupMap = f.GroupMap
		p.auto = f.AutoGroupMap
		p.fallback = f.FallbackNoMap
		if f.MaxHops > 0 {
			p.maxHops = f.MaxHops
		}
		if f.UseGroupHops {
			p.hopLimits = f.GroupHopLimits
		}
		p.noAlerts, p.noArchive, p.missions, p.disabled = f.NoAlerts, f.NoArchive, f.Missions, f.Disabled
		if f.MissionsDefault != nil {
			p.missionOn = *f.MissionsDefault
		}
		if f.Name != "" {
			p.name = f.Name
		}
	}
	for _, g := range append(slices.Clone(p.in), p.out...) {
		s.dir.EnsureGroup(g, "Federation", false)
	}
	if p.maxHops <= 0 {
		p.maxHops = DefaultConfig().Federation.MaxHops
	}
	return p
}

func (p *fedPolicy) missionAllowed(name string) bool {
	if p == nil {
		return true
	}
	if v, ok := p.missions[name]; ok {
		return v
	}
	return p.missionOn
}

func (s *Server) fedClient(kind, name, remote string, p *fedPolicy) *Client {
	in, out := s.dir.Mask(p.in), s.dir.Mask(p.out)
	id := &Identity{Via: kind, In: in, Out: out, Anon: true}
	if in.Empty() && out.Empty() {
		id = s.dir.Anonymous()
	}
	c := s.hub.NewClient(kind, remote, id)
	c.Name = name
	c.authed.Store(true)
	c.fed = p
	return c
}

func (s *Server) inboundMask(c *Client, remote []string) (GroupMask, bool) {
	p := c.fed
	if p == nil || len(remote) == 0 {
		return c.InMask(), true
	}
	var mapped []string
	for _, g := range remote {
		if locals, ok := p.groupMap[g]; ok {
			for _, l := range locals {
				if _, exists := s.dir.Group(l); exists && !slices.Contains(mapped, l) {
					mapped = append(mapped, l)
				}
			}
			continue
		}
		if p.auto || slices.Contains(p.in, g) {
			if _, exists := s.dir.Group(g); exists && !slices.Contains(mapped, g) {
				mapped = append(mapped, g)
			}
		}
	}
	if len(mapped) > 0 {
		return s.dir.Mask(mapped), true
	}
	if len(p.groupMap) > 0 && !p.fallback && !p.auto {
		return nil, false
	}
	return c.InMask(), true
}

func (s *Server) outboundGroups(c *Client, m *Message, hops int64) ([]string, bool) {
	p := c.fed
	out := []string{}
	if p != nil {
		out = p.out
	}
	groups := s.fedGroups(m, out)
	if p == nil || len(p.hopLimits) == 0 {
		return groups, true
	}
	var kept []string
	for _, g := range groups {
		if lim, ok := p.hopLimits[g]; ok && lim > 0 && hops > int64(lim) {
			continue
		}
		kept = append(kept, g)
	}
	return kept, len(kept) > 0 || len(groups) == 0
}

type seenFederate struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Remote           string    `json:"remote"`
	CAFingerprint    string    `json:"caFingerprint,omitempty"`
	Subject          string    `json:"subject,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	Version          string    `json:"version"`
	Direction        string    `json:"direction"`
	LastConnected    time.Time `json:"lastConnected"`
	LastDisconnected time.Time `json:"lastDisconnected,omitempty"`
	RemoteGroups     []string  `json:"remoteGroups,omitempty"`
}

func openSeenFederates(dataDir string) (*store.Collection[seenFederate], error) {
	return store.Open[seenFederate](filepath.Join(dataDir, "db", "federates-seen.jsonl"), true)
}

func (s *Server) noteFederate(p *fedPolicy, remote, version, dir string, cert *x509.Certificate, connected bool) {
	if s.fedSeen == nil || p == nil {
		return
	}
	key := firstNonEmpty(p.id, "link:"+p.name)
	s.fedSeen.Update(key, func(v seenFederate, exists bool) (seenFederate, bool, error) {
		v.ID, v.Name, v.Remote, v.Version, v.Direction = key, p.name, remote, version, dir
		if p.caFP != "" {
			v.CAFingerprint = p.caFP
		}
		if cert != nil {
			v.Subject, v.Issuer = cert.Subject.String(), cert.Issuer.String()
		}
		if connected {
			v.LastConnected = time.Now().UTC()
		} else {
			v.LastDisconnected = time.Now().UTC()
		}
		return v, true, nil
	})
}

func (s *Server) noteRemoteGroups(p *fedPolicy, groups []string) {
	if s.fedSeen == nil || p == nil {
		return
	}
	key := firstNonEmpty(p.id, "link:"+p.name)
	s.fedSeen.Update(key, func(v seenFederate, exists bool) (seenFederate, bool, error) {
		if !exists {
			return v, false, nil
		}
		v.RemoteGroups = slices.Clone(groups)
		return v, true, nil
	})
}

func (s *Server) federateLastSeen(p *fedPolicy) time.Time {
	if s.fedSeen == nil || p == nil {
		return time.Time{}
	}
	v, ok := s.fedSeen.Get(firstNonEmpty(p.id, "link:"+p.name))
	if !ok {
		return time.Time{}
	}
	return v.LastDisconnected
}

func (s *Server) fileBlocked(name string, data []byte) bool {
	ff := s.Config().Federation.FileFilter
	if !ff.Enabled {
		return false
	}
	exts := ff.Extensions
	if len(exts) == 0 {
		exts = []string{"pref"}
	}
	blocked := func(n string) bool {
		ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(n)), ".")
		return slices.ContainsFunc(exts, func(e string) bool { return strings.EqualFold(strings.TrimPrefix(e, "."), ext) })
	}
	if blocked(name) {
		return true
	}
	for _, entry := range zipEntryNames(data) {
		if blocked(entry) {
			return true
		}
	}
	return false
}

func rolMissionName(rol takproto.ROL) string {
	_, resource, params := parseROL(rol.Program)
	if resource != "mission" && resource != "data_feed" {
		return ""
	}
	var v struct {
		MissionName string `json:"missionName"`
		Name        string `json:"name"`
	}
	if jsonUnmarshalLoose(params, &v) != nil {
		return ""
	}
	return firstNonEmpty(v.MissionName, v.Name)
}
