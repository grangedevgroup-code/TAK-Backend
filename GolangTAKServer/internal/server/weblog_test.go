package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebPolicyAndLogs(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.Web = WebConfig{AccessLog: true, AuditLog: true, CORSOrigins: []string{"https://ops.example.org"}, CustomHeaders: []string{"X-Test: yes"}}
	})
	a := adminHeaders(t, s)
	req, _ := http.NewRequest("OPTIONS", plainURL(s, "/Marti/api/missions"), nil)
	req.Header.Set("Origin", "https://ops.example.org")
	req.Header.Set("Access-Control-Request-Method", "GET")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "https://ops.example.org" {
		t.Fatalf("preflight: %d %v", resp.StatusCode, resp.Header)
	}
	req, _ = http.NewRequest("GET", plainURL(s, "/Marti/api/missions"), nil)
	req.Header.Set("Origin", "https://evil.example.org")
	req.Header.Set("Authorization", a["Authorization"])
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != "" || resp.Header.Get("X-Test") != "yes" {
		t.Fatalf("headers: %v", resp.Header)
	}
	time.Sleep(100 * time.Millisecond)
	audit, _ := os.ReadFile(filepath.Join(s.DataDir, "logs", "audit.log"))
	if !strings.Contains(string(audit), `"user":"boss"`) || !strings.Contains(string(audit), `"/Marti/api/missions"`) {
		t.Fatalf("audit log: %s", audit)
	}
	access, _ := os.ReadFile(filepath.Join(s.DataDir, "logs", "access.log"))
	if !strings.Contains(string(access), "boss") || !strings.Contains(string(access), "GET /Marti/api/missions") {
		t.Fatalf("access log: %s", access)
	}
}
