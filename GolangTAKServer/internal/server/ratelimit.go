package server

import (
	"sync"
	"time"
)

type RateLimitConfig struct {
	Enabled          bool    `json:"enabled"`
	ReadPerSec       float64 `json:"readPerSec"`
	ReadBurst        int     `json:"readBurst"`
	DeliveryPerSec   float64 `json:"deliveryPerSec"`
	DeliveryBurst    int     `json:"deliveryBurst"`
	ConnectPerMinute int     `json:"connectPerMinute"`
}

func defaultRateLimits() RateLimitConfig {
	return RateLimitConfig{ReadPerSec: 20, ReadBurst: 100, DeliveryPerSec: 200, DeliveryBurst: 1000, ConnectPerMinute: 30}
}

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (b *tokenBucket) allow(rate float64, burst int, now time.Time) bool {
	if rate <= 0 {
		return true
	}
	if burst < 1 {
		burst = 1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = float64(burst)
	} else {
		b.tokens += now.Sub(b.last).Seconds() * rate
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type connLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
	last time.Time
}

func (l *connLimiter) allow(ip string, perMinute int, now time.Time) bool {
	if perMinute <= 0 || ip == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	cut := now.Add(-time.Minute)
	if now.Sub(l.last) > time.Minute {
		for k, v := range l.hits {
			if len(v) == 0 || v[len(v)-1].Before(cut) {
				delete(l.hits, k)
			}
		}
		l.last = now
	}
	list := l.hits[ip]
	i := 0
	for i < len(list) && list[i].Before(cut) {
		i++
	}
	list = list[i:]
	if len(list) >= perMinute {
		l.hits[ip] = list
		return false
	}
	l.hits[ip] = append(list, now)
	return true
}

func rateExempt(m *Message) bool {
	if m == nil || m.Event == nil {
		return true
	}
	e := m.Event
	if e.Is("b-a") || e.Is("b-t-f") || e.IsDelete() || e.IsControl() || len(e.Dests()) > 0 {
		return true
	}
	return m.Source != nil && m.Source.Kind == KindPeer
}

func (h *Hub) SetRateLimits(c RateLimitConfig) {
	h.limits.Store(&c)
}

func (h *Hub) rateLimits() *RateLimitConfig {
	if l := h.limits.Load(); l != nil && l.Enabled {
		return l
	}
	return nil
}

func (h *Hub) allowRead(c *Client, m *Message) bool {
	l := h.rateLimits()
	if l == nil || c.Kind == KindPeer || rateExempt(m) {
		return true
	}
	if c.readBucket.allow(l.ReadPerSec, l.ReadBurst, time.Now()) {
		return true
	}
	h.RateDropped.Add(1)
	c.rateDrops.Add(1)
	return false
}

func (h *Hub) allowDelivery(c *Client, m *Message) bool {
	l := h.rateLimits()
	if l == nil || c.Kind == KindPeer || rateExempt(m) {
		return true
	}
	if c.sendBucket.allow(l.DeliveryPerSec, l.DeliveryBurst, time.Now()) {
		return true
	}
	h.RateDropped.Add(1)
	c.rateDrops.Add(1)
	return false
}

func (h *Hub) allowConnect(ip string) bool {
	l := h.rateLimits()
	if l == nil {
		return true
	}
	if h.connects.allow(ip, l.ConnectPerMinute, time.Now()) {
		return true
	}
	h.RateRefused.Add(1)
	return false
}
