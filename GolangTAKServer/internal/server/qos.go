package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

type QoSRule struct {
	ClientThresholdCount      int `json:"clientThresholdCount"`
	ReportingRateLimitSeconds int `json:"reportingRateLimitSeconds"`
}

type DOSRule struct {
	ClientThresholdCount    int `json:"clientThresholdCount"`
	MessageLimitPerInterval int `json:"messageLimitPerInterval"`
}

type QoSConfig struct {
	DeliveryEnabled    bool      `json:"deliveryEnabled,omitempty"`
	DeliveryRules      []QoSRule `json:"deliveryRules,omitempty"`
	ReadEnabled        bool      `json:"readEnabled,omitempty"`
	ReadRules          []QoSRule `json:"readRules,omitempty"`
	DOSEnabled         bool      `json:"dosEnabled,omitempty"`
	DOSIntervalSeconds int       `json:"dosIntervalSeconds,omitempty"`
	DOSRules           []DOSRule `json:"dosRules,omitempty"`
}

func defaultQoSRules() []QoSRule {
	return []QoSRule{{1000, 120}, {5000, 180}, {10000, 240}, {25000, 480}, {50000, 960}}
}

func defaultDOSRules() []DOSRule {
	return []DOSRule{{0, 6000}, {1000, 3000}, {5000, 1500}}
}

func (q QoSConfig) withDefaults() QoSConfig {
	if len(q.DeliveryRules) == 0 {
		q.DeliveryRules = defaultQoSRules()
	}
	if len(q.ReadRules) == 0 {
		q.ReadRules = defaultQoSRules()
	}
	if len(q.DOSRules) == 0 {
		q.DOSRules = defaultDOSRules()
	}
	if q.DOSIntervalSeconds <= 0 {
		q.DOSIntervalSeconds = 60
	}
	return q
}

func activeQoSRule(rules []QoSRule, clients int) (QoSRule, bool) {
	best, ok := QoSRule{}, false
	for _, r := range rules {
		if clients >= r.ClientThresholdCount && (!ok || r.ClientThresholdCount >= best.ClientThresholdCount) {
			best, ok = r, true
		}
	}
	return best, ok
}

func activeDOSRule(rules []DOSRule, clients int) (DOSRule, bool) {
	best, ok := DOSRule{}, false
	for _, r := range rules {
		if clients >= r.ClientThresholdCount && (!ok || r.ClientThresholdCount >= best.ClientThresholdCount) {
			best, ok = r, true
		}
	}
	return best, ok
}

type qosClientState struct {
	mu        sync.Mutex
	lastRead  time.Time
	delivered map[string]time.Time
	dosStart  time.Time
	dosCount  int
}

func (h *Hub) SetQoS(q QoSConfig) {
	q = q.withDefaults()
	h.qos.Store(&q)
}

func (h *Hub) qosConfig() *QoSConfig {
	return h.qos.Load()
}

func qosApplies(m *Message) bool {
	return !rateExempt(m) && m.Event.IsSA()
}

func (h *Hub) qosAllowRead(c *Client, m *Message) bool {
	q := h.qosConfig()
	if q == nil || c.Relay || rateExempt(m) {
		return true
	}
	clients := int(h.nonRelay.Load())
	now := time.Now()
	st := &c.qos
	st.mu.Lock()
	defer st.mu.Unlock()
	if q.DOSEnabled {
		if r, ok := activeDOSRule(q.DOSRules, clients); ok && r.MessageLimitPerInterval > 0 {
			if now.Sub(st.dosStart) > time.Duration(q.DOSIntervalSeconds)*time.Second {
				st.dosStart, st.dosCount = now, 0
			}
			st.dosCount++
			if st.dosCount > r.MessageLimitPerInterval {
				return false
			}
		}
	}
	if q.ReadEnabled && qosApplies(m) {
		if r, ok := activeQoSRule(q.ReadRules, clients); ok && r.ReportingRateLimitSeconds > 0 {
			if now.Sub(st.lastRead) < time.Duration(r.ReportingRateLimitSeconds)*time.Second {
				return false
			}
			st.lastRead = now
		}
	}
	return true
}

func (h *Hub) qosAllowDelivery(c *Client, m *Message) bool {
	q := h.qosConfig()
	if q == nil || !q.DeliveryEnabled || c.Relay || !qosApplies(m) {
		return true
	}
	r, ok := activeQoSRule(q.DeliveryRules, int(h.nonRelay.Load()))
	if !ok || r.ReportingRateLimitSeconds <= 0 {
		return true
	}
	now := time.Now()
	st := &c.qos
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.delivered == nil {
		st.delivered = map[string]time.Time{}
	}
	uid := m.Event.UID
	if last, seen := st.delivered[uid]; seen && now.Sub(last) < time.Duration(r.ReportingRateLimitSeconds)*time.Second {
		return false
	}
	st.delivered[uid] = now
	if len(st.delivered) > 20000 {
		cut := now.Add(-time.Duration(r.ReportingRateLimitSeconds) * time.Second)
		for k, t := range st.delivered {
			if t.Before(cut) {
				delete(st.delivered, k)
			}
		}
	}
	return true
}

func (s *Server) qosConfJSON() map[string]any {
	q := s.Config().QoS.withDefaults()
	rules := func(list []QoSRule) []QoSRule {
		out := append([]QoSRule(nil), list...)
		sort.Slice(out, func(i, j int) bool { return out[i].ClientThresholdCount < out[j].ClientThresholdCount })
		return out
	}
	return map[string]any{
		"deliveryRateLimiter": map[string]any{"enabled": q.DeliveryEnabled, "rateLimitRule": rules(q.DeliveryRules)},
		"readRateLimiter":     map[string]any{"enabled": q.ReadEnabled, "rateLimitRule": rules(q.ReadRules)},
		"dosRateLimiter":      map[string]any{"enabled": q.DOSEnabled, "intervalSeconds": q.DOSIntervalSeconds, "dosLimitRule": q.DOSRules},
	}
}

func (s *Server) qosConf(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Qos", s.qosConfJSON()))
}

func (s *Server) qosEnable(which string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var on bool
		if err := json.NewDecoder(io.LimitReader(r.Body, 64)).Decode(&on); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "send true or false"))
			return
		}
		_, err := s.UpdateConfig(func(c *Config) error {
			switch which {
			case "delivery":
				c.QoS.DeliveryEnabled = on
			case "read":
				c.QoS.ReadEnabled = on
			case "dos":
				c.QoS.DOSEnabled = on
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, s.envelope("java.lang.Boolean", on))
	}
}

func (s *Server) qosSetRules(which string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var rules []QoSRule
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rules); err != nil || len(rules) == 0 {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "send a list of rate limit rules"))
			return
		}
		for _, rule := range rules {
			if rule.ClientThresholdCount < 0 || rule.ReportingRateLimitSeconds < 0 {
				writeJSON(w, http.StatusBadRequest, s.envelope("error", "rule values cannot be negative"))
				return
			}
		}
		_, err := s.UpdateConfig(func(c *Config) error {
			if which == "delivery" {
				c.QoS.DeliveryRules = rules
			} else {
				c.QoS.ReadRules = rules
			}
			return nil
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.config.Qos", s.qosConfJSON()))
	}
}

func (s *Server) qosActive(which string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := s.Config().QoS.withDefaults()
		clients := s.hub.Count()
		var out any = nil
		switch which {
		case "delivery":
			if rule, ok := activeQoSRule(q.DeliveryRules, clients); ok && q.DeliveryEnabled {
				out = rule.ReportingRateLimitSeconds
			}
		case "read":
			if rule, ok := activeQoSRule(q.ReadRules, clients); ok && q.ReadEnabled {
				out = rule.ReportingRateLimitSeconds
			}
		case "dos":
			if rule, ok := activeDOSRule(q.DOSRules, clients); ok && q.DOSEnabled {
				out = rule.MessageLimitPerInterval
			}
		}
		if out == nil {
			out = -1
		}
		writeJSON(w, http.StatusOK, s.envelope("java.lang.Integer", out))
	}
}

func (s *Server) qosRoutes(a func(string, http.HandlerFunc)) {
	a("GET /Marti/api/qos/conf", s.qosConf)
	a("PUT /Marti/api/qos/delivery/enable", s.qosEnable("delivery"))
	a("PUT /Marti/api/qos/read/enable", s.qosEnable("read"))
	a("PUT /Marti/api/qos/dos/enable", s.qosEnable("dos"))
	a("PUT /Marti/api/qos/delivery/set", s.qosSetRules("delivery"))
	a("PUT /Marti/api/qos/read/set", s.qosSetRules("read"))
	a("GET /Marti/api/qos/ratelimit/delivery/active", s.qosActive("delivery"))
	a("GET /Marti/api/qos/ratelimit/read/active", s.qosActive("read"))
	a("GET /Marti/api/qos/ratelimit/dos/active", s.qosActive("dos"))
}
