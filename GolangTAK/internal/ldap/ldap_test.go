package ldap

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

type fakeUser struct {
	dn, password string
	attrs        map[string][]string
}

type fakeServer struct {
	ln      net.Listener
	users   map[string]fakeUser
	mu      sync.Mutex
	filters []element
}

func filterText(e element) string {
	switch e.tag {
	case 0xa0, 0xa1:
		op := "&"
		if e.tag == 0xa1 {
			op = "|"
		}
		s := "(" + op
		for _, c := range e.children {
			s += filterText(c)
		}
		return s + ")"
	case 0xa2:
		return "(!" + filterText(e.children[0]) + ")"
	case 0xa3:
		return "(" + e.children[0].str() + "=" + e.children[1].str() + ")"
	case 0x87:
		return "(" + e.str() + "=*)"
	case 0xa4:
		s := "(" + e.children[0].str() + "="
		for _, p := range e.children[1].children {
			switch p.tag {
			case 0x80:
				s += p.str() + "*"
			case 0x81:
				s += "*" + p.str() + "*"
			case 0x82:
				s += "*" + p.str()
			}
		}
		return s + ")"
	}
	return "?"
}

func matches(e element, u fakeUser) bool {
	switch e.tag {
	case 0xa0:
		for _, c := range e.children {
			if !matches(c, u) {
				return false
			}
		}
		return true
	case 0xa1:
		for _, c := range e.children {
			if matches(c, u) {
				return true
			}
		}
		return false
	case 0xa2:
		return !matches(e.children[0], u)
	case 0xa3:
		for _, v := range u.attrs[strings.ToLower(e.children[0].str())] {
			if strings.EqualFold(v, e.children[1].str()) {
				return true
			}
		}
	case 0x87:
		return len(u.attrs[strings.ToLower(e.str())]) > 0 || strings.EqualFold(e.str(), "objectClass")
	}
	return false
}

func newFake(t *testing.T) *fakeServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{ln: ln, users: map[string]fakeUser{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeServer) reply(c net.Conn, id int64, op []byte) {
	c.Write(seq(tagSequence, encInt(tagInteger, id), op))
}

func ldapResult(tag byte, code int64, msg string) []byte {
	return seq(tag, encInt(tagEnumerated, code), encStr(tagOctetString, ""), encStr(tagOctetString, msg))
}

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	bound := ""
	for {
		m, err := readMessage(r, 1<<20)
		if err != nil || len(m.children) < 2 {
			return
		}
		id := m.children[0].int()
		op := m.children[1]
		switch op.tag {
		case opBindRequest:
			dn, pw := op.children[1].str(), op.children[2].str()
			code := int64(resultInvalidCredentials)
			if dn == "cn=service,dc=example,dc=org" && pw == "service-pw" {
				code = 0
			}
			for _, u := range f.users {
				if strings.EqualFold(u.dn, dn) && u.password == pw && pw != "" {
					code = 0
				}
			}
			if code == 0 {
				bound = dn
			}
			f.reply(c, id, ldapResult(opBindResponse, code, ""))
		case opSearchRequest:
			if bound == "" {
				f.reply(c, id, ldapResult(opSearchDone, 50, "insufficient access"))
				continue
			}
			base := op.children[0].str()
			scope := op.children[1].int()
			filter := op.children[6]
			f.mu.Lock()
			f.filters = append(f.filters, filter)
			f.mu.Unlock()
			for _, u := range f.users {
				if scope == ScopeBase && !strings.EqualFold(u.dn, base) {
					continue
				}
				if scope == ScopeSubtree && (!strings.HasSuffix(strings.ToLower(u.dn), strings.ToLower(base)) || !matches(filter, u)) {
					continue
				}
				var attrs [][]byte
				for k, vs := range u.attrs {
					var vals [][]byte
					for _, v := range vs {
						vals = append(vals, encStr(tagOctetString, v))
					}
					attrs = append(attrs, seq(tagSequence, encStr(tagOctetString, k), seq(tagSet, vals...)))
				}
				f.reply(c, id, seq(opSearchEntry, encStr(tagOctetString, u.dn), seq(tagSequence, attrs...)))
			}
			f.reply(c, id, ldapResult(opSearchDone, 0, ""))
		case opUnbindRequest:
			return
		default:
			f.reply(c, id, ldapResult(0x78, 2, "unsupported"))
		}
	}
}

func TestAuthenticateWithServiceAccount(t *testing.T) {
	f := newFake(t)
	f.users["alice"] = fakeUser{dn: "uid=alice,ou=people,dc=example,dc=org", password: "alice-pw", attrs: map[string][]string{
		"uid": {"alice"}, "cn": {"Alice Smith"}, "memberof": {"cn=tak_Blue,ou=groups,dc=example,dc=org", "cn=tak_admins,ou=groups,dc=example,dc=org"}, "takcallsign": {"ALPHA-1"},
	}}
	cfg := Config{URL: "ldap://" + f.ln.Addr().String(), BindDN: "cn=service,dc=example,dc=org", BindPassword: "service-pw", BaseDN: "dc=example,dc=org", Attributes: []string{"takCallsign"}}
	e, err := Authenticate(cfg, "alice", "alice-pw")
	if err != nil {
		t.Fatal(err)
	}
	if e.DN != "uid=alice,ou=people,dc=example,dc=org" || e.First("takCallsign") != "ALPHA-1" || len(e.Groups) != 2 {
		t.Fatalf("entry %+v", e)
	}
	if CommonName(e.Groups[0]) != "tak_Blue" {
		t.Fatalf("cn %q", CommonName(e.Groups[0]))
	}
	if _, err := Authenticate(cfg, "alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := Authenticate(cfg, "alice", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password: %v", err)
	}
	if _, err := Authenticate(cfg, "nobody", "x"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := Authenticate(cfg, "*)(uid=*", "x"); err == nil {
		t.Fatal("filter injection accepted")
	}
	f.mu.Lock()
	last := f.filters[len(f.filters)-1]
	f.mu.Unlock()
	if last.tag != 0xa1 || len(last.children) != 3 {
		t.Fatalf("injected filter changed the structure: %s", filterText(last))
	}
	for _, c := range last.children {
		if c.tag != 0xa3 || c.children[1].str() != "*)(uid=*" {
			t.Fatalf("user name not kept as a literal value: %s", filterText(last))
		}
	}
	bad := cfg
	bad.BindPassword = "nope"
	if _, err := Authenticate(bad, "alice", "alice-pw"); err == nil || !strings.Contains(err.Error(), "service account") {
		t.Fatalf("bad service account: %v", err)
	}
}

func TestAuthenticateDirectBind(t *testing.T) {
	f := newFake(t)
	f.users["bob"] = fakeUser{dn: "uid=bob,ou=people,dc=example,dc=org", password: "bob-pw", attrs: map[string][]string{"uid": {"bob"}, "memberof": {"cn=Red,ou=groups,dc=example,dc=org"}}}
	cfg := Config{URL: "ldap://" + f.ln.Addr().String(), UserDN: "uid={user},ou=people,dc=example,dc=org"}
	e, err := Authenticate(cfg, "bob", "bob-pw")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Groups) != 1 || CommonName(e.Groups[0]) != "Red" {
		t.Fatalf("groups %v", e.Groups)
	}
	if _, err := Authenticate(cfg, "bob", "nope"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestFilters(t *testing.T) {
	for in, want := range map[string]string{
		"(uid=alice)":                     "(uid=alice)",
		"(&(objectClass=person)(uid=a*))": "(&(objectClass=*)(uid=a*))",
		"(|(cn=x)(!(mail=*)))":            "(|(cn=x)(!(mail=*)))",
		"uid=bob":                         "(uid=bob)",
		"(cn=a\\2ab)":                     "(cn=a*b)",
	} {
		b, err := compileFilter(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		e, _, err := parseOne(b)
		if err != nil {
			t.Fatal(err)
		}
		got := filterText(e)
		if in == "(&(objectClass=person)(uid=a*))" {
			if got != "(&(objectClass=person)(uid=a*))" {
				t.Fatalf("%s -> %s", in, got)
			}
			continue
		}
		if got != want {
			t.Fatalf("%s -> %s want %s", in, got, want)
		}
	}
	for _, bad := range []string{"(", "(uid)", "(&)", "((uid=a)", "(cn=a\\zz)"} {
		if _, err := compileFilter(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if got := EscapeFilter("a*b(c)d\\e"); got != `a\2ab\28c\29d\5ce` {
		t.Fatalf("escape %s", got)
	}
	if got := EscapeDN(" a,b=c "); got != `\ a\,b\=c\ ` {
		t.Fatalf("escape dn %q", got)
	}
	if CommonName(`cn=Smith\, John,ou=x`) != "Smith, John" {
		t.Fatalf("cn %q", CommonName(`cn=Smith\, John,ou=x`))
	}
}
