package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

const KindTelegram = "telegram"

type TelegramConfig struct {
	Enabled   bool   `json:"enabled"`
	Token     string `json:"token,omitempty"`
	ChatID    string `json:"chatId"`
	Group     string `json:"group,omitempty"`
	Chat      bool   `json:"chat"`
	Alerts    bool   `json:"alerts"`
	Locations bool   `json:"locations"`
	APIURL    string `json:"apiUrl,omitempty"`
}

type telegramBridge struct {
	s       *Server
	cfg     TelegramConfig
	client  *Client
	hc      *http.Client
	in, out atomic.Int64
	mu      sync.Mutex
	lastErr string
	botName string
}

type tgUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	IsBot     bool   `json:"is_bot"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	Date     int64  `json:"date"`
	Text     string `json:"text"`
	Caption  string `json:"caption"`
	Location *struct {
		Latitude           float64  `json:"latitude"`
		Longitude          float64  `json:"longitude"`
		HorizontalAccuracy *float64 `json:"horizontal_accuracy"`
		Heading            *float64 `json:"heading"`
		LivePeriod         int      `json:"live_period"`
	} `json:"location"`
}

type tgUpdate struct {
	UpdateID      int64      `json:"update_id"`
	Message       *tgMessage `json:"message"`
	EditedMessage *tgMessage `json:"edited_message"`
}

func (u *tgUser) name() string {
	if u == nil {
		return "Telegram"
	}
	n := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if n == "" {
		n = u.Username
	}
	return firstNonEmpty(n, "Telegram "+strconv.FormatInt(u.ID, 10))
}

func (b *telegramBridge) api() string {
	return strings.TrimRight(firstNonEmpty(b.cfg.APIURL, "https://api.telegram.org"), "/") + "/bot" + b.cfg.Token + "/"
}

func (b *telegramBridge) call(ctx context.Context, method string, in any, out any) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.api()+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return errors.New(strings.ReplaceAll(ue.Err.Error(), b.cfg.Token, "TOKEN"))
		}
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var env struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("telegram %s: HTTP %d", method, resp.StatusCode)
	}
	if !env.OK {
		return fmt.Errorf("telegram %s: %s", method, firstNonEmpty(env.Description, "HTTP "+strconv.Itoa(resp.StatusCode)))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (b *telegramBridge) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.lastErr = ""
		return
	}
	if b.lastErr != err.Error() {
		b.s.log.Warn("Telegram bridge", "err", err)
	}
	b.lastErr = err.Error()
}

func (s *Server) startTelegram() {
	cfg := s.Config().Telegram
	if !cfg.Enabled || cfg.Token == "" || cfg.ChatID == "" {
		return
	}
	b := &telegramBridge{s: s, cfg: cfg, hc: &http.Client{Timeout: 60 * time.Second}}
	var groups []string
	if cfg.Group != "" {
		if _, err := s.dir.EnsureGroup(cfg.Group, "Telegram", false); err == nil {
			groups = []string{cfg.Group}
		}
	}
	b.client = s.relayClient(KindTelegram, "Telegram", "telegram", groups)
	b.client.filter = func(*Message) bool { return false }
	s.hub.Add(b.client)
	s.telegram = b
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		defer s.hub.Remove(b.client)
		b.pollLoop()
	}()
	go func() {
		defer s.wg.Done()
		b.sendLoop()
	}()
	s.log.Info("Telegram bridge started", "chat", cfg.ChatID)
}

func (b *telegramBridge) pollLoop() {
	var me tgUser
	ctx, cancel := context.WithTimeout(b.s.ctx, 30*time.Second)
	if err := b.call(ctx, "getMe", map[string]any{}, &me); err != nil {
		b.setErr(err)
	} else {
		b.mu.Lock()
		b.botName = me.Username
		b.mu.Unlock()
	}
	cancel()
	offset := int64(0)
	delay := time.Second
	for b.s.ctx.Err() == nil {
		var ups []tgUpdate
		ctx, cancel := context.WithTimeout(b.s.ctx, 50*time.Second)
		err := b.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 25, "allowed_updates": []string{"message", "edited_message"}}, &ups)
		cancel()
		if err != nil {
			if b.s.ctx.Err() != nil {
				return
			}
			b.setErr(err)
			select {
			case <-b.s.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, 2*time.Minute)
			continue
		}
		b.setErr(nil)
		delay = time.Second
		for _, u := range ups {
			offset = max(offset, u.UpdateID+1)
			if u.Message != nil {
				b.handle(u.Message)
			}
			if u.EditedMessage != nil && u.EditedMessage.Location != nil {
				b.handle(u.EditedMessage)
			}
		}
	}
}

func (b *telegramBridge) publish(e *cot.Event, chat bool) {
	m := NewMessage(e, b.client, b.client.InMask())
	m.Everyone = b.cfg.Group == ""
	m.NoReplay = chat
	b.s.hub.Publish(m)
	b.in.Add(1)
}

func (b *telegramBridge) handle(msg *tgMessage) {
	if strconv.FormatInt(msg.Chat.ID, 10) != strings.TrimSpace(b.cfg.ChatID) || msg.From == nil || msg.From.IsBot {
		return
	}
	uid := "telegram-" + strconv.FormatInt(msg.From.ID, 10)
	name := msg.From.name()
	if msg.Location != nil && b.cfg.Locations {
		lat, lon := msg.Location.Latitude, msg.Location.Longitude
		if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
			return
		}
		stale := 10 * time.Minute
		if msg.Location.LivePeriod > 0 {
			stale = time.Duration(msg.Location.LivePeriod) * time.Second
		}
		e := cot.New(uid, "a-f-G-U-C", "m-g", stale)
		e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
		if a := msg.Location.HorizontalAccuracy; a != nil && *a > 0 {
			e.Point.Ce = *a
		}
		e.Detail.AddNew("contact", "callsign", name)
		if h := msg.Location.Heading; h != nil {
			e.Detail.AddNew("track", "course", cot.FormatFloat(*h))
		}
		e.Detail.AddNew("remarks").Text = "Shared from Telegram"
		b.publish(e, false)
		return
	}
	text := strings.TrimSpace(firstNonEmpty(msg.Text, msg.Caption))
	if text == "" || strings.HasPrefix(text, "/") || !b.cfg.Chat {
		return
	}
	if len(text) > 2000 {
		text = text[:2000]
	}
	e := cot.Chat(uid, name, "All Chat Rooms", "All Chat Rooms", text, nil)
	b.publish(e, true)
}

func telegramAlertText(e *cot.Event) string {
	kind := map[string]string{"b-a-o-tbl": "911 alert", "b-a-o-pan": "Ring the bell", "b-a-g": "Geofence breach", "b-a-o-opn": "Troops in contact", "b-a-o-can": "Emergency cancelled"}[e.Type]
	if kind == "" {
		kind = "Alert"
	}
	who := e.Callsign()
	if em := e.D("emergency"); em != nil {
		kind = firstNonEmpty(em.Attr("type"), kind)
		if em.Attr("cancel") == "true" {
			kind = "Emergency cancelled"
		}
	}
	return fmt.Sprintf("%s: %s at %.5f, %.5f", kind, firstNonEmpty(who, e.UID), e.Point.Lat, e.Point.Lon)
}

func (b *telegramBridge) sendLoop() {
	mask := b.client.InMask()
	sub := b.s.hub.Subscribe(256, func(m *Message) bool {
		if m.Source == b.client || (m.Source != nil && m.Source.Kind == KindTelegram) {
			return false
		}
		e := m.Event
		chat := b.cfg.Chat && e.IsChat() && broadcastChat(e)
		alert := b.cfg.Alerts && strings.HasPrefix(e.Type, "b-a-")
		if !chat && !alert {
			return false
		}
		return b.cfg.Group == "" || m.Everyone || m.Groups.Intersects(mask)
	})
	defer b.s.hub.Unsubscribe(sub)
	seenAlert := map[string]time.Time{}
	for {
		select {
		case <-b.s.ctx.Done():
			return
		case m := <-sub.C:
			e := m.Event
			var text string
			if e.IsChat() {
				body := strings.TrimSpace(e.Remarks())
				if body == "" {
					continue
				}
				from := e.Callsign()
				if ch := e.D("__chat"); ch != nil {
					from = firstNonEmpty(ch.Attr("senderCallsign"), from)
				}
				text = firstNonEmpty(from, "TAK") + ": " + body
			} else {
				key := e.UID + "|" + e.Type
				if t, ok := seenAlert[key]; ok && time.Since(t) < 5*time.Minute {
					continue
				}
				seenAlert[key] = time.Now()
				text = telegramAlertText(e)
			}
			ctx, cancel := context.WithTimeout(b.s.ctx, 30*time.Second)
			err := b.call(ctx, "sendMessage", map[string]any{"chat_id": b.cfg.ChatID, "text": text, "disable_web_page_preview": true}, nil)
			cancel()
			if err != nil {
				b.setErr(err)
				continue
			}
			b.out.Add(1)
		}
	}
}

func (s *Server) apiTelegram(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config().Telegram
	out := map[string]any{"enabled": cfg.Enabled, "running": s.telegram != nil}
	if b := s.telegram; b != nil {
		b.mu.Lock()
		out["error"], out["bot"] = b.lastErr, b.botName
		b.mu.Unlock()
		out["received"], out["sent"] = b.in.Load(), b.out.Load()
	}
	if r.Method == http.MethodPost {
		if s.telegram == nil {
			apiError(w, http.StatusBadRequest, errors.New("save the Telegram settings and restart first"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		err := s.telegram.call(ctx, "sendMessage", map[string]any{"chat_id": cfg.ChatID, "text": "Test message from " + s.Config().Name}, nil)
		if err != nil {
			apiError(w, http.StatusBadGateway, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, out)
}
