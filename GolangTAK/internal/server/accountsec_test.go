package server

import (
	"bufio"
	"encoding/base32"
	"encoding/json"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTOTPReferenceValues(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for step, want := range map[int64]string{1: "287082", 37037036: "081804", 37037037: "050471", 41152263: "005924"} {
		if got, _ := totpAt(secret, step); got != want {
			t.Fatalf("step %d: got %s want %s", step, got, want)
		}
	}
}

type fakeSMTP struct {
	mu   sync.Mutex
	msgs []string
	addr string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				w := func(s string) { c.Write([]byte(s + "\r\n")) }
				w("220 test")
				var data strings.Builder
				inData := false
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if line == ".\r\n" {
							inData = false
							f.mu.Lock()
							f.msgs = append(f.msgs, data.String())
							f.mu.Unlock()
							data.Reset()
							w("250 ok")
							continue
						}
						data.WriteString(line)
						continue
					}
					cmd := strings.ToUpper(strings.Fields(line + " x")[0])
					switch cmd {
					case "EHLO", "HELO":
						w("250 test")
					case "DATA":
						inData = true
						w("354 go")
					case "QUIT":
						w("221 bye")
						return
					default:
						w("250 ok")
					}
				}
			}(c)
		}
	}()
	return f
}

func (f *fakeSMTP) last(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.msgs)
		var m string
		if n > 0 {
			m = f.msgs[n-1]
			f.msgs = nil
		}
		f.mu.Unlock()
		if n > 0 {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no email sent")
	return ""
}

func emailServer(t *testing.T, tweak func(*EmailConfig)) (*Server, *fakeSMTP) {
	f := startFakeSMTP(t)
	host, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	s := newTestServer(t, func(c *Config) {
		c.Email = EmailConfig{Enabled: true, Host: host, Port: p, Security: "none", From: "GolangTAK <tak@example.org>", PublicURL: "https://tak.example.org"}
		if tweak != nil {
			tweak(&c.Email)
		}
	})
	return s, f
}

func postJSON(t *testing.T, c *http.Client, url string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	h := map[string]string{"Content-Type": "application/json", "X-Requested-With": "GolangTAK"}
	for k, v := range hdr {
		h[k] = v
	}
	st, resp := doReq(t, c, "POST", url, strings.NewReader(string(b)), h)
	var out map[string]any
	json.Unmarshal(resp, &out)
	return st, out
}

func TestTwoFactorLogin(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("pilot", "pilot-password", false, nil)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	st, out := postJSON(t, c, plainURL(s, "/api/login"), map[string]string{"username": "pilot", "password": "pilot-password"}, nil)
	if st != 200 || out["csrf"] == nil {
		t.Fatalf("login: %d %v", st, out)
	}
	csrf := map[string]string{"X-CSRF-Token": out["csrf"].(string)}
	_, setup := postJSON(t, c, plainURL(s, "/api/account/2fa/totp"), nil, csrf)
	secret := setup["secret"].(string)
	if !strings.Contains(setup["qr"].(string), "<svg") {
		t.Fatal("no QR code")
	}
	if st, _ := postJSON(t, c, plainURL(s, "/api/account/2fa/enable"), map[string]string{"method": "totp", "code": "000000"}, csrf); st != http.StatusBadRequest {
		t.Fatal("wrong code enabled 2FA")
	}
	code, _ := totpAt(secret, time.Now().Unix()/30)
	st, en := postJSON(t, c, plainURL(s, "/api/account/2fa/enable"), map[string]string{"method": "totp", "code": code}, csrf)
	if st != 200 || len(en["recoveryCodes"].([]any)) != 10 {
		t.Fatalf("enable: %d %v", st, en)
	}
	recovery := en["recoveryCodes"].([]any)[0].(string)

	fresh := &http.Client{}
	st, out = postJSON(t, fresh, plainURL(s, "/api/login"), map[string]string{"username": "pilot", "password": "pilot-password"}, nil)
	if st != 200 || out["twoFactor"] != "totp" || out["csrf"] != nil {
		t.Fatalf("password alone signed in: %v", out)
	}
	if st, _ := postJSON(t, fresh, plainURL(s, "/api/login/verify"), map[string]string{"challenge": out["challenge"].(string), "code": code}, nil); st != http.StatusUnauthorized {
		t.Fatal("the same code was accepted twice")
	}
	st, done := postJSON(t, fresh, plainURL(s, "/api/login/verify"), map[string]string{"challenge": out["challenge"].(string), "code": recovery}, nil)
	if st != 200 || done["csrf"] == nil {
		t.Fatalf("recovery code: %d %v", st, done)
	}
	_, out = postJSON(t, fresh, plainURL(s, "/api/login"), map[string]string{"username": "pilot", "password": "pilot-password"}, nil)
	if st, _ := postJSON(t, fresh, plainURL(s, "/api/login/verify"), map[string]string{"challenge": out["challenge"].(string), "code": recovery}, nil); st != http.StatusUnauthorized {
		t.Fatal("a recovery code worked twice")
	}
	if _, err := s.dir.CheckPassword("1.1.1.1", "pilot", "pilot-password"); err != nil {
		t.Fatal("TAK client password sign-in must not need a second factor")
	}
}

func TestPasswordChangeEndsOldPassword(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("ops", "first-password", false, nil)
	if _, err := s.dir.CheckPassword("1.1.1.1", "ops", "first-password"); err != nil {
		t.Fatal(err)
	}
	s.dir.SetPassword("ops", "second-password")
	if _, err := s.dir.CheckPassword("1.1.1.1", "ops", "first-password"); err == nil {
		t.Fatal("the old password still works after a change")
	}
}

var linkRe = regexp.MustCompile(`#/(reset|verify)/([A-Za-z0-9_-]+)`)

func TestEmailResetAndRegistration(t *testing.T) {
	s, mail := emailServer(t, func(e *EmailConfig) {
		e.AllowRegistration, e.ApproveRegistrations = true, true
		e.AllowedDomains = []string{".mil", "example.org"}
	})
	s.dir.AddUser("chief", "chief-password", true, nil)
	s.dir.UpdateUser("chief", func(u *User) error { u.Email = "chief@example.org"; return nil })

	st, _ := postJSON(t, http.DefaultClient, plainURL(s, "/api/password/forgot"), map[string]string{"login": "chief@example.org"}, nil)
	if st != 200 {
		t.Fatal(st)
	}
	m := linkRe.FindStringSubmatch(mail.last(t))
	if m == nil || m[1] != "reset" {
		t.Fatal("no reset link")
	}
	if st, _ := postJSON(t, http.DefaultClient, plainURL(s, "/api/password/reset"), map[string]string{"token": m[2], "password": "brand-new-pass"}, nil); st != 200 {
		t.Fatal("reset failed")
	}
	if _, err := s.dir.CheckPassword("1.1.1.2", "chief", "brand-new-pass"); err != nil {
		t.Fatal("new password does not work")
	}
	if st, _ := postJSON(t, http.DefaultClient, plainURL(s, "/api/password/reset"), map[string]string{"token": m[2], "password": "again-new-pass"}, nil); st != http.StatusBadRequest {
		t.Fatal("reset link worked twice")
	}

	if st, _ := postJSON(t, http.DefaultClient, plainURL(s, "/api/register"), map[string]string{"username": "rando", "email": "x@gmail.com", "password": "rando-password"}, nil); st != http.StatusForbidden {
		t.Fatalf("blocked domain registered: %d", st)
	}
	if st, out := postJSON(t, http.DefaultClient, plainURL(s, "/api/register"), map[string]string{"username": "soldier", "email": "soldier@army.mil", "password": "soldier-password"}, nil); st != 200 {
		t.Fatalf("register: %d %v", st, out)
	}
	if _, err := s.dir.CheckPassword("1.1.1.3", "soldier", "soldier-password"); err == nil {
		t.Fatal("unverified account can sign in")
	}
	m = linkRe.FindStringSubmatch(mail.last(t))
	if m == nil || m[1] != "verify" {
		t.Fatal("no verify link")
	}
	if st, _ := postJSON(t, http.DefaultClient, plainURL(s, "/api/register/verify"), map[string]string{"token": m[2]}, nil); st != 200 {
		t.Fatal("verify failed")
	}
	if u, _ := s.dir.User("soldier"); u.Pending != "approval" || !u.Disabled {
		t.Fatalf("account should wait for approval: %+v", u.Pending)
	}
	admin := adminToken(t, s)
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/users/soldier/approve"), nil, admin); st != http.StatusNoContent {
		t.Fatal("approve failed")
	}
	if _, err := s.dir.CheckPassword("1.1.1.4", "soldier", "soldier-password"); err != nil {
		t.Fatal("approved account cannot sign in")
	}
}
