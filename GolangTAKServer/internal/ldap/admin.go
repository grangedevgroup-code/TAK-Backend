package ldap

import (
	"sort"
)

const (
	opModifyRequest  = 0x66
	opModifyResponse = 0x67
	opAddRequest     = 0x68
	opAddResponse    = 0x69
	opDelRequest     = 0x4a
	opDelResponse    = 0x6b

	ModAdd     = 0
	ModDelete  = 1
	ModReplace = 2
)

type Change struct {
	Op     int
	Attr   string
	Values []string
}

type Admin struct {
	c   *conn
	cfg Config
}

func OpenAdmin(cfg Config) (*Admin, error) {
	c, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.BindDN != "" {
		if err := c.bind(cfg.BindDN, cfg.BindPassword); err != nil {
			c.close()
			return nil, err
		}
	}
	return &Admin{c: c, cfg: cfg}, nil
}

func (a *Admin) Close() { a.c.close() }

func (a *Admin) Search(base, filter string, attrs []string, limit int) ([]Entry, error) {
	return a.c.search(base, ScopeSubtree, filter, attrs, limit)
}

func (a *Admin) Read(dn string, attrs []string) (*Entry, error) {
	list, err := a.c.search(dn, ScopeBase, "(objectClass=*)", attrs, 1)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrUserNotFound
	}
	return &list[0], nil
}

func attrList(attrs map[string][]string) []byte {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts [][]byte
	for _, k := range keys {
		var vals [][]byte
		for _, v := range attrs[k] {
			vals = append(vals, encStr(tagOctetString, v))
		}
		if len(vals) == 0 {
			continue
		}
		parts = append(parts, seq(tagSequence, encStr(tagOctetString, k), seq(tagSet, vals...)))
	}
	return seq(tagSequence, parts...)
}

func (a *Admin) roundTrip(op []byte, want byte) error {
	id, err := a.c.send(op)
	if err != nil {
		return err
	}
	resp, err := a.c.read(id)
	if err != nil {
		return err
	}
	if resp.tag != want {
		return errBER
	}
	return result(resp)
}

func (a *Admin) Add(dn string, attrs map[string][]string) error {
	return a.roundTrip(seq(opAddRequest, encStr(tagOctetString, dn), attrList(attrs)), opAddResponse)
}

func (a *Admin) Modify(dn string, changes []Change) error {
	var parts [][]byte
	for _, ch := range changes {
		var vals [][]byte
		for _, v := range ch.Values {
			vals = append(vals, encStr(tagOctetString, v))
		}
		parts = append(parts, seq(tagSequence, encInt(tagEnumerated, int64(ch.Op)), seq(tagSequence, encStr(tagOctetString, ch.Attr), seq(tagSet, vals...))))
	}
	return a.roundTrip(seq(opModifyRequest, encStr(tagOctetString, dn), seq(tagSequence, parts...)), opModifyResponse)
}

func (a *Admin) Delete(dn string) error {
	return a.roundTrip(tlv(opDelRequest, []byte(dn)), opDelResponse)
}
