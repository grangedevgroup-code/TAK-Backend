package server

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/ldap"
)

func TestLDAPGroupMapping(t *testing.T) {
	e := &ldap.Entry{DN: "uid=a,dc=x", Attrs: map[string][]string{"takcallsign": {" ALPHA-1 "}}, Groups: []string{
		"CN=tak_Blue,OU=Groups,DC=corp", "cn=tak_Red,ou=groups,dc=corp", "CN=Domain Users,CN=Users,DC=corp", "CN=TAK Admins,OU=Groups,DC=corp", "cn=tak_Blue,ou=other",
	}}
	got := mapLDAPEntry(LDAPConfig{GroupPrefix: "tak_", AdminGroup: "tak admins", CallsignAttribute: "takCallsign"}, e)
	if !got.Admin || got.Callsign != "ALPHA-1" || !slices.Equal(got.Groups, []string{"Blue", "Red"}) {
		t.Fatalf("%+v", got)
	}
	all := mapLDAPEntry(LDAPConfig{}, e)
	if all.Admin || len(all.Groups) != 4 || !slices.Contains(all.Groups, "Domain Users") {
		t.Fatalf("%+v", all)
	}
}

func TestExternalSignIn(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
	calls := 0
	s.dir.External = func(name, pw string) (*ExternalAuth, error) {
		calls++
		if name == "carol" && pw == "carol-ldap" {
			return &ExternalAuth{Groups: []string{"Blue", "Ops"}, Admin: false, Callsign: "CAROL"}, nil
		}
		if name == "dan" && pw == "dan-ldap" {
			return &ExternalAuth{Admin: true}, nil
		}
		if name == "local" {
			return &ExternalAuth{Admin: true}, nil
		}
		return nil, ldap.ErrInvalidCredentials
	}
	id, err := s.dir.CheckPassword("1.1.1.1", "carol", "carol-ldap")
	if err != nil {
		t.Fatal(err)
	}
	if id.Admin || !slices.Equal(s.dir.Names(id.In), []string{"Blue", "Ops"}) {
		t.Fatalf("identity %+v groups %v", id, s.dir.Names(id.In))
	}
	u, ok := s.dir.User("carol")
	if !ok || !u.External || u.Callsign != "CAROL" || u.Hash != "" {
		t.Fatalf("user %+v", u)
	}
	if _, err := s.dir.CheckPassword("1.1.1.1", "carol", "carol-ldap"); err != nil || calls != 1 {
		t.Fatalf("second sign-in should come from the cache: %v calls=%d", err, calls)
	}
	if _, err := s.dir.CheckPassword("1.1.1.2", "carol", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	id, err = s.dir.CheckPassword("1.1.1.3", "dan", "dan-ldap")
	if err != nil || !id.Admin || !slices.Equal(s.dir.Names(id.In), []string{"__ANON__"}) {
		t.Fatalf("dan: %v %+v", err, id)
	}
	if _, err := s.dir.AddUser("local", "local-password", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.dir.CheckPassword("1.1.1.4", "local", "anything-else"); err == nil {
		t.Fatal("external directory overrode a local account")
	}
	if _, err := s.dir.CheckPassword("1.1.1.4", "local", "local-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.dir.UpdateUser("carol", func(u *User) error { u.Disabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	s.dir.vmu.Lock()
	delete(s.dir.verified, "carol")
	s.dir.vmu.Unlock()
	if _, err := s.dir.CheckPassword("1.1.1.5", "carol", "carol-ldap"); err == nil {
		t.Fatal("disabled external user signed in")
	}
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/me"), nil, map[string]string{"basic": "dan:dan-ldap", "X-Requested-With": "t"})
	if st != 200 || !strings.Contains(string(body), `"admin":true`) {
		t.Fatalf("dashboard sign-in for an LDAP admin: %d %s", st, body)
	}
}

func TestLDAPOffByDefault(t *testing.T) {
	s := newTestServer(t, nil)
	if _, err := s.ldapAuth("x", "y"); !errors.Is(err, errLDAPOff) {
		t.Fatalf("%v", err)
	}
}
