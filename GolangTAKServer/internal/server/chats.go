package server

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type StoredChat struct {
	ID       string    `json:"id"`
	UID      string    `json:"uid,omitempty"`
	Callsign string    `json:"callsign,omitempty"`
	XML      string    `json:"xml"`
	From     string    `json:"from"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

type Chats struct {
	db *store.Collection[StoredChat]
}

func OpenChats(dataDir string) (*Chats, error) {
	db, err := store.Open[StoredChat](filepath.Join(dataDir, "db", "pending-chat.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &Chats{db: db}, nil
}

func (c *Chats) Close() { c.db.Close() }

func (s *Server) storeOffline(d cot.Dest, m *Message) {
	e := m.Event
	if !e.IsChat() || e.Type != "b-t-f" {
		return
	}
	days := s.Config().Retention.ChatDays
	if days <= 0 {
		return
	}
	if d.UID == "" && d.Callsign != "" {
		if dev, ok := s.devices.ByCallsign(d.Callsign); ok {
			d.UID = dev.UID
		}
	}
	if d.UID == "" && d.Callsign == "" {
		return
	}
	from := ""
	if m.Source != nil {
		from = m.Source.UID()
	}
	sc := StoredChat{ID: cot.NewUID(), UID: d.UID, Callsign: d.Callsign, XML: string(m.XML()), From: from, Created: time.Now().UTC(), Expires: time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)}
	if err := s.chats.db.Put(sc.ID, sc); err == nil {
		s.log.Info("message stored for offline recipient", "to", firstNonEmpty(d.Callsign, d.UID), "from", from)
	}
}

func (s *Server) deliverStored(c *Client) {
	info := c.Info()
	if info.UID == "" && info.Callsign == "" {
		return
	}
	now := time.Now()
	for _, sc := range s.chats.db.All() {
		if now.After(sc.Expires) {
			s.chats.db.Delete(sc.ID)
			continue
		}
		match := (sc.UID != "" && sc.UID == info.UID) || (sc.UID == "" && sc.Callsign != "" && strings.EqualFold(sc.Callsign, info.Callsign))
		if !match {
			continue
		}
		e, err := cot.Parse([]byte(sc.XML))
		if err != nil {
			s.chats.db.Delete(sc.ID)
			continue
		}
		msg := NewMessage(e, nil, nil)
		msg.NoReplay = true
		if c.Send(msg) {
			s.chats.db.Delete(sc.ID)
		}
	}
}

func (s *Server) expireChats() {
	now := time.Now()
	for _, sc := range s.chats.db.All() {
		if now.After(sc.Expires) {
			s.chats.db.Delete(sc.ID)
		}
	}
}

func (s *Server) PendingChats() []StoredChat { return s.chats.db.All() }
