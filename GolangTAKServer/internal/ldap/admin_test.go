package ldap

import (
	"strings"
	"testing"
)

func TestAdminAddModifyDelete(t *testing.T) {
	f := newFake(t)
	cfg := Config{URL: "ldap://" + f.ln.Addr().String(), BindDN: "cn=service,dc=example,dc=org", BindPassword: "service-pw"}
	a, err := OpenAdmin(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	dn := "uid=carol,ou=People,dc=example,dc=org"
	if err := a.Add(dn, map[string][]string{"objectClass": {"top", "inetOrgPerson"}, "uid": {"carol"}, "cn": {"Carol"}, "sn": {"C"}, "userPassword": {"pw1"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(dn, map[string][]string{"uid": {"carol"}}); err == nil {
		t.Fatal("duplicate add accepted")
	}
	if err := a.Modify(dn, []Change{{Op: ModReplace, Attr: "mail", Values: []string{"carol@example.org"}}, {Op: ModAdd, Attr: "description", Values: []string{"medic"}}}); err != nil {
		t.Fatal(err)
	}
	e, err := a.Read(dn, nil)
	if err != nil || e.First("mail") != "carol@example.org" || e.First("description") != "medic" {
		t.Fatalf("read back: %+v %v", e, err)
	}
	list, err := a.Search("ou=People,dc=example,dc=org", "(uid=carol)", nil, 10)
	if err != nil || len(list) != 1 || !strings.EqualFold(list[0].DN, dn) {
		t.Fatalf("search: %+v %v", list, err)
	}
	if err := a.Delete(dn); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Read(dn, nil); err == nil {
		t.Fatal("entry still readable after delete")
	}
}
