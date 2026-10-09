package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
)

type fakeTelegram struct {
	mu      sync.Mutex
	pending []map[string]any
	sent    []string
	nextID  int64
}

func (f *fakeTelegram) queue(msg map[string]any, edited bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	key := "message"
	if edited {
		key = "edited_message"
	}
	f.pending = append(f.pending, map[string]any{"update_id": f.nextID, key: msg})
}

func (f *fakeTelegram) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/botTEST-TOKEN/") {
			w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		switch strings.TrimPrefix(r.URL.Path, "/botTEST-TOKEN/") {
		case "getMe":
			w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true,"username":"golangtak_bot"}}`))
		case "getUpdates":
			off, _ := body["offset"].(float64)
			deadline := time.Now().Add(2 * time.Second)
			for {
				f.mu.Lock()
				var out []map[string]any
				for _, u := range f.pending {
					if u["update_id"].(int64) >= int64(off) {
						out = append(out, u)
					}
				}
				f.mu.Unlock()
				if len(out) > 0 || time.Now().After(deadline) {
					json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": out})
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		case "sendMessage":
			if body["chat_id"] != "-1001" {
				t.Errorf("sent to chat %v", body["chat_id"])
			}
			f.mu.Lock()
			f.sent = append(f.sent, body["text"].(string))
			f.mu.Unlock()
			w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			w.Write([]byte(`{"ok":false,"description":"unknown method"}`))
		}
	})
}

func (f *fakeTelegram) sentText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.sent, "\n")
}

func TestTelegramBridge(t *testing.T) {
	fake := &fakeTelegram{}
	ts := httptest.NewServer(fake.handler(t))
	defer ts.Close()
	s := newTestServer(t, func(c *Config) {
		c.Telegram = TelegramConfig{Enabled: true, Token: "TEST-TOKEN", ChatID: "-1001", Chat: true, Alerts: true, Locations: true, APIURL: ts.URL}
	})
	tak := dialTCP(t, s)
	tak.send(saXML("ANDROID-tg", "WOLF", 38.9, -77.0))

	from := map[string]any{"id": 42, "first_name": "Dana", "last_name": "Ruiz"}
	fake.queue(map[string]any{"message_id": 1, "from": from, "chat": map[string]any{"id": -1001}, "text": "Road blocked at the bridge"}, false)
	tak.expect(func(e *cot.Event) bool { return e.IsChat() && e.Remarks() == "Road blocked at the bridge" }, "chat from Telegram")

	fake.queue(map[string]any{"message_id": 2, "from": from, "chat": map[string]any{"id": -1001}, "location": map[string]any{"latitude": 38.95, "longitude": -77.05, "live_period": 900}}, false)
	loc := tak.expect(uidIs("telegram-42"), "position from Telegram")
	if loc.Callsign() != "Dana Ruiz" || loc.Point.Lat != 38.95 {
		t.Fatalf("position: %s", loc)
	}
	fake.queue(map[string]any{"message_id": 3, "from": map[string]any{"id": 7, "first_name": "Eve"}, "chat": map[string]any{"id": -999}, "text": "spoofed"}, false)
	tak.expectNone(func(e *cot.Event) bool { return e.IsChat() && e.Remarks() == "spoofed" }, "message from another chat", time.Second)

	tak.send(cot.Chat("ANDROID-tg", "WOLF", "All Chat Rooms", "All Chat Rooms", "Copy, rerouting", nil).String())
	waitFor(t, "chat sent to Telegram", 5*time.Second, func() bool { return strings.Contains(fake.sentText(), "WOLF: Copy, rerouting") })

	em := cot.New("ANDROID-tg-9-1-1", "b-a-o-tbl", "h-e", time.Minute)
	em.Point = cot.Point{Lat: 38.9, Lon: -77.0, Hae: 0, Ce: 5, Le: 5}
	em.Detail.AddNew("contact", "callsign", "WOLF-Alert")
	em.Detail.AddNew("emergency", "type", "911 Alert").Text = "WOLF"
	tak.send(em.String())
	waitFor(t, "alert sent to Telegram", 5*time.Second, func() bool { return strings.Contains(fake.sentText(), "911 Alert: WOLF-Alert") })
	if strings.Contains(fake.sentText(), "Road blocked") {
		t.Fatal("a Telegram message was echoed back to Telegram")
	}

	admin := feedAdmin(t, s)
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/settings"), nil, admin)
	if st != 200 || strings.Contains(string(body), "TEST-TOKEN") {
		t.Fatalf("settings leaked the bot token: %d", st)
	}
	_, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/telegram"), nil, admin)
	if !strings.Contains(string(body), `"bot":"golangtak_bot"`) {
		t.Fatalf("status: %s", body)
	}
}
