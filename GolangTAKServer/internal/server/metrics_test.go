package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrometheusMetrics(t *testing.T) {
	s := newTestServer(t, nil)
	url := plainURL(s, "/metrics")
	if st, _ := doReq(t, http.DefaultClient, "GET", url, nil, nil); st != http.StatusNotFound {
		t.Fatalf("metrics served while off: %d", st)
	}
	s.UpdateConfig(func(c *Config) error {
		c.Metrics = MetricsConfig{Enabled: true, Token: "scrape-token-123"}
		return nil
	})
	c := dialTCP(t, s)
	c.send(saXML("metrics-client", "MET", 1, 1))
	time.Sleep(200 * time.Millisecond)

	if st, _ := doReq(t, http.DefaultClient, "GET", url, nil, nil); st != http.StatusUnauthorized {
		t.Fatalf("anonymous read: %d", st)
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", url, nil, map[string]string{"Authorization": "Bearer wrong"}); st != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", st)
	}
	st, body := doReq(t, http.DefaultClient, "GET", url, nil, map[string]string{"Authorization": "Bearer scrape-token-123"})
	text := string(body)
	if st != 200 {
		t.Fatalf("token read: %d %s", st, text)
	}
	for _, want := range []string{
		"# TYPE golangtakserver_clients gauge",
		`golangtakserver_clients{kind="tcp"} 1`,
		"golangtakserver_messages_received_total",
		`golangtakserver_info{version="test"`,
		"go_goroutines",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if f := strings.Fields(line); len(f) != 2 {
			t.Fatalf("bad sample line %q", line)
		}
	}
	s.dir.AddUser("metricsadmin", "metrics-admin-pw", true, nil)
	if st, _ := doReq(t, http.DefaultClient, "GET", url, nil, map[string]string{"basic": "metricsadmin:metrics-admin-pw"}); st != 200 {
		t.Fatalf("admin read: %d", st)
	}
	s.dir.AddUser("metricsuser", "metrics-user-pw", false, nil)
	if st, _ := doReq(t, http.DefaultClient, "GET", url, nil, map[string]string{"basic": "metricsuser:metrics-user-pw"}); st != http.StatusUnauthorized {
		t.Fatalf("normal user read: %d", st)
	}
}
