// Package plugin is the toolkit for GolangTAK server plugins written in Go.
//
// A server plugin is any program GolangTAK starts, supervises and restarts.
// Load reads the connection details GolangTAK passes in the environment, and
// the returned Plugin talks to the server through its REST API and live event
// stream. Plugins in other languages use the same environment variables and
// HTTP endpoints.
package plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/websocket"
)

// Event is one CoT event from the live stream.
type Event struct {
	UID      string    `json:"uid"`
	Type     string    `json:"type"`
	Callsign string    `json:"callsign"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Hae      float64   `json:"hae"`
	Time     time.Time `json:"time"`
	Stale    time.Time `json:"stale"`
	Team     string    `json:"team,omitempty"`
	Remarks  string    `json:"remarks,omitempty"`
	Source   string    `json:"source,omitempty"`
	Chat     string    `json:"chat,omitempty"`
	To       string    `json:"to,omitempty"`
	XML      string    `json:"xml,omitempty"`
}

// IsChat reports whether the event is a GeoChat message.
func (e Event) IsChat() bool { return strings.HasPrefix(e.Type, "b-t-f") }

// IsDevice reports whether the event is a friendly unit, which is how TAK
// clients report their own position.
func (e Event) IsDevice() bool { return strings.HasPrefix(e.Type, "a-f-") }

// Plugin holds the connection to the server that started this program.
type Plugin struct {
	Name       string
	ServerName string
	URL        string
	StreamURL  string
	Token      string
	DataDir    string
	HTTPAddr   string
	Settings   map[string]string
	Log        *log.Logger

	client *http.Client
	tls    *tls.Config
}

// ErrNotPlugin is returned by Load when the program was not started by GolangTAK.
var ErrNotPlugin = errors.New("not started by GolangTAK: add it with golangtak plugin add or golangtak plugin install")

// Load reads the environment GolangTAK provides to plugins.
func Load() (*Plugin, error) {
	p := &Plugin{
		Name:       os.Getenv("GOLANGTAK_PLUGIN"),
		ServerName: os.Getenv("GOLANGTAK_SERVER_NAME"),
		URL:        strings.TrimRight(os.Getenv("GOLANGTAK_URL"), "/"),
		StreamURL:  os.Getenv("GOLANGTAK_STREAM_URL"),
		Token:      os.Getenv("GOLANGTAK_TOKEN"),
		DataDir:    os.Getenv("GOLANGTAK_PLUGIN_DATA"),
		HTTPAddr:   os.Getenv("GOLANGTAK_PLUGIN_HTTP"),
		Settings:   map[string]string{},
		Log:        log.New(os.Stderr, "", 0),
	}
	if p.URL == "" || p.Token == "" {
		return nil, ErrNotPlugin
	}
	if raw := os.Getenv("GOLANGTAK_PLUGIN_SETTINGS"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &p.Settings); err != nil {
			return nil, fmt.Errorf("plugin settings: %w", err)
		}
	}
	p.tls = &tls.Config{MinVersion: tls.VersionTLS12}
	if pem, err := os.ReadFile(os.Getenv("GOLANGTAK_CA")); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		p.tls.RootCAs = pool
	}
	p.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: p.tls}}
	return p, nil
}

// Setting returns a setting from the plugin's settings form, or def when it is empty.
func (p *Plugin) Setting(key, def string) string {
	if v := p.Settings[key]; v != "" {
		return v
	}
	return def
}

// SettingInt returns a numeric setting, or def when it is empty or not a number.
func (p *Plugin) SettingInt(key string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(p.Settings[key])); err == nil {
		return n
	}
	return def
}

// SettingBool returns a checkbox setting.
func (p *Plugin) SettingBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(p.Settings[key])) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// APIError is a non-success answer from the server's REST API.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

// Do calls the server's REST API. body is sent as JSON unless it is an
// io.Reader, and the answer is decoded into out when out is not nil.
func (p *Plugin) Do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case io.Reader:
		rd = b
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return err
		}
		rd, ctype = bytes.NewReader(data), "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &APIError{Status: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Chat sends a GeoChat message. to is a callsign, or empty for All Chat Rooms.
func (p *Plugin) Chat(ctx context.Context, to, text string) error {
	sender := p.Name
	if sender == "" {
		sender = "Server"
	}
	return p.Do(ctx, http.MethodPost, "/api/chat", map[string]string{"message": text, "to": to, "sender": sender}, nil)
}

// SendCoT publishes a CoT event given as XML.
func (p *Plugin) SendCoT(ctx context.Context, xml string) error {
	return p.Do(ctx, http.MethodPost, "/api/cot", xml, nil)
}

// Marker places or moves a point on every device's map.
type Marker struct {
	UID      string  `json:"uid,omitempty"`
	Callsign string  `json:"callsign"`
	Type     string  `json:"type,omitempty"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Remarks  string  `json:"remarks,omitempty"`
	StaleSec int     `json:"staleSeconds,omitempty"`
}

// PlaceMarker creates or updates a marker and returns its UID.
func (p *Plugin) PlaceMarker(ctx context.Context, m Marker) (string, error) {
	var out struct {
		UID string `json:"uid"`
	}
	if err := p.Do(ctx, http.MethodPost, "/api/markers", m, &out); err != nil {
		return "", err
	}
	return out.UID, nil
}

// Events calls fn for every event the plugin's account may see, reconnecting
// after errors, until ctx ends. With full set, events carry their CoT XML.
func (p *Plugin) Events(ctx context.Context, full bool, fn func(Event)) error {
	u := p.StreamURL
	if u == "" {
		return errors.New("the server has no HTTP port for the event stream")
	}
	if full {
		u += "?format=full"
	}
	delay := time.Second
	for {
		err := p.listen(ctx, u, fn)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.Log.Printf("event stream closed (%v); reconnecting in %s", err, delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func (p *Plugin) listen(ctx context.Context, u string, fn func(Event)) error {
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, _, err := websocket.Dial(dctx, u, &websocket.DialOptions{TLS: p.tls, Header: http.Header{"Authorization": {"Bearer " + p.Token}}})
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	stop := context.AfterFunc(ctx, func() { conn.CloseNow() })
	defer stop()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var e Event
		if json.Unmarshal(data, &e) == nil {
			fn(e)
		}
	}
}

// User is the signed-in dashboard user making a request to the plugin's pages.
type User struct {
	Name   string
	Admin  bool
	Groups []string
}

// UserOf returns who is using the plugin's web pages. GolangTAK signs the user
// in and passes these details through its proxy; requests that did not come
// through the proxy have no user.
func UserOf(r *http.Request) (User, bool) {
	name := r.Header.Get("X-GolangTAK-User")
	if name == "" {
		return User{}, false
	}
	u := User{Name: name, Admin: r.Header.Get("X-GolangTAK-Admin") == "true"}
	for _, g := range strings.Split(r.Header.Get("X-GolangTAK-Groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			u.Groups = append(u.Groups, g)
		}
	}
	return u, true
}

// Serve runs the plugin's web pages and API at /plugins/NAME/ on the
// dashboard. The plugin must declare "http": true in plugin.json. Paths
// arrive without the /plugins/NAME prefix.
func (p *Plugin) Serve(ctx context.Context, h http.Handler) error {
	if p.HTTPAddr == "" {
		return errors.New(`the plugin has no web address; set "http": true in plugin.json`)
	}
	host, _, err := net.SplitHostPort(p.HTTPAddr)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return fmt.Errorf("unexpected plugin web address %q", p.HTTPAddr)
	}
	hs := &http.Server{Addr: p.HTTPAddr, Handler: h, ReadHeaderTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// PagePath returns the dashboard address of a path inside the plugin's pages.
func (p *Plugin) PagePath(path string) string {
	return "/plugins/" + url.PathEscape(p.Name) + "/" + strings.TrimLeft(path, "/")
}
