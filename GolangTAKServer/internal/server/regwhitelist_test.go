package server

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"testing"
)

func TestRegistrationGroupsRules(t *testing.T) {
	ec := EmailConfig{RegistrationGroups: []string{"Default"}, Whitelist: []RegistrationWhitelist{
		{Domain: "partner.org", PrivateGroup: true, Groups: []string{"Shared"}},
		{Domain: ".mil", Group: "Military"},
		{Domain: "agency.gov", Token: "T0KEN", Group: "Agency"},
		{Domain: "", Token: "ANYDOMAIN"},
	}}
	cases := []struct {
		addr, token string
		ok          bool
		groups      []string
	}{
		{"bob@partner.org", "", true, []string{"partner.org", "Shared"}},
		{"bob@sub.partner.org", "", true, []string{"partner.org", "Shared"}},
		{"bob@notpartner.org", "", false, nil},
		{"sam@army.mil", "", true, []string{"Military"}},
		{"amy@agency.gov", "", false, nil},
		{"amy@agency.gov", "wrong", false, nil},
		{"amy@agency.gov", "T0KEN", true, []string{"Agency"}},
		{"amy@other.org", "T0KEN", false, nil},
		{"zed@anywhere.net", "ANYDOMAIN", true, []string{"Default"}},
	}
	for _, c := range cases {
		g, ok := registrationGroups(ec, c.addr, c.token)
		if ok != c.ok || (ok && !slices.Equal(g, c.groups)) {
			t.Errorf("%s token %q: %v %v, want %v %v", c.addr, c.token, g, ok, c.groups, c.ok)
		}
	}
	if g, ok := registrationGroups(EmailConfig{RegistrationGroups: []string{"Default"}}, "x@y.org", ""); !ok || !slices.Equal(g, []string{"Default"}) {
		t.Errorf("no whitelist: %v %v", g, ok)
	}
	if _, ok := registrationGroups(EmailConfig{}, "x@y.org", "token"); ok {
		t.Error("a token was accepted without a whitelist")
	}
}

func TestRegistrationWhitelistSignUp(t *testing.T) {
	s, mail := emailServer(t, func(e *EmailConfig) {
		e.AllowRegistration = true
		e.Whitelist = []RegistrationWhitelist{{Domain: "partner.org", PrivateGroup: true, Groups: []string{"Shared"}}, {Domain: "agency.gov", Token: "T0KEN", Group: "Agency"}}
	})
	signUp := func(addr, token string) int {
		t.Helper()
		q := url.Values{"emailAddress": {addr}}
		if token != "" {
			q.Set("token", token)
		}
		resp, err := http.Post(plainURL(s, "/register/user?"+q.Encode()), "application/x-www-form-urlencoded", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	link := regexp.MustCompile(`/register/token/([A-Za-z0-9_-]+)`)
	confirm := func(name string, want ...string) {
		t.Helper()
		m := link.FindStringSubmatch(mail.last(t))
		if m == nil {
			t.Fatal("no confirmation link")
		}
		resp, err := http.Get(plainURL(s, "/register/token/"+m[1]))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		u, ok := s.dir.User(name)
		if !ok {
			t.Fatalf("%s was not created", name)
		}
		for _, g := range want {
			if !slices.Contains(u.In, g) {
				t.Fatalf("%s groups %v, want %v", name, u.In, want)
			}
		}
	}
	if st := signUp("eve@other.org", ""); st != http.StatusForbidden {
		t.Fatalf("unlisted domain: %d", st)
	}
	if st := signUp("amy@agency.gov", ""); st != http.StatusForbidden {
		t.Fatalf("token-only domain without a token: %d", st)
	}
	if st := signUp("amy@agency.gov", "wrong"); st != http.StatusForbidden {
		t.Fatalf("wrong token: %d", st)
	}
	if st := signUp("bob@partner.org", ""); st != http.StatusOK {
		t.Fatalf("listed domain: %d", st)
	}
	confirm(userNameFromEmail("bob@partner.org"), "partner.org", "Shared")
	if st := signUp("amy@agency.gov", "T0KEN"); st != http.StatusOK {
		t.Fatalf("token sign-up: %d", st)
	}
	confirm(userNameFromEmail("amy@agency.gov"), "Agency")
}
