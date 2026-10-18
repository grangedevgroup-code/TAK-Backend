package server

import (
	"net/http"
	"testing"
)

func TestLoginPageRedirectsToDashboard(t *testing.T) {
	s := newTestServer(t, nil)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(plainURL(s, "/login"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("GET /login: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
