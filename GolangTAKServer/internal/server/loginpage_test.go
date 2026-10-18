package server

import (
	"net/http"
	"net/url"
	"strings"
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

func TestFormLogin(t *testing.T) {
	s := newTestServer(t, nil)
	if _, err := s.dir.AddUser("formuser", "form-pass-1234", false, nil); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	post := func(user, pass, origin string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("POST", plainURL(s, "/login"), strings.NewReader(url.Values{"username": {user}, "password": {pass}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := post("formuser", "wrong", ""); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/login?error" || len(r.Cookies()) != 0 {
		t.Fatalf("bad password: %d %q %v", r.StatusCode, r.Header.Get("Location"), r.Cookies())
	}
	if r := post("formuser", "form-pass-1234", "https://evil.example"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site form sign-in: %d", r.StatusCode)
	}
	r := post("formuser", "form-pass-1234", "")
	if r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/" {
		t.Fatalf("form sign-in: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	var sess *http.Cookie
	for _, ck := range r.Cookies() {
		if ck.Name == sessionCookie {
			sess = ck
		}
	}
	if sess == nil {
		t.Fatal("no session cookie")
	}
	req, _ := http.NewRequest("GET", plainURL(s, "/api/me"), nil)
	req.AddCookie(sess)
	me, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	me.Body.Close()
	if me.StatusCode != http.StatusOK {
		t.Fatalf("session from form sign-in: %d", me.StatusCode)
	}
}
