package ldap

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("ldap: invalid user name or password")
	ErrUserNotFound       = errors.New("ldap: user not found")
)

const (
	opBindRequest      = 0x60
	opBindResponse     = 0x61
	opUnbindRequest    = 0x42
	opSearchRequest    = 0x63
	opSearchEntry      = 0x64
	opSearchDone       = 0x65
	opSearchReference  = 0x73
	opExtendedRequest  = 0x77
	opExtendedResponse = 0x78

	ScopeBase    = 0
	ScopeSubtree = 2

	resultSuccess            = 0
	resultInvalidCredentials = 49
	startTLSOID              = "1.3.6.1.4.1.1466.20037"
)

type Config struct {
	URL          string
	StartTLS     bool
	Insecure     bool
	RootCAs      *x509.CertPool
	BindDN       string
	BindPassword string
	BaseDN       string
	UserFilter   string
	UserDN       string
	GroupFilter  string
	GroupBaseDN  string
	Attributes   []string
	Timeout      time.Duration
}

type Entry struct {
	DN     string
	Attrs  map[string][]string
	Groups []string
}

func (e *Entry) Get(attr string) []string {
	if e == nil {
		return nil
	}
	return e.Attrs[strings.ToLower(attr)]
}

func (e *Entry) First(attr string) string {
	if v := e.Get(attr); len(v) > 0 {
		return v[0]
	}
	return ""
}

type Error struct {
	Code    int64
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("ldap: result %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("ldap: result %d", e.Code)
}

type conn struct {
	c       net.Conn
	r       *bufio.Reader
	id      int64
	timeout time.Duration
}

func dial(cfg Config) (*conn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("ldap: invalid server URL %q", cfg.URL)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	host := u.Hostname()
	port := u.Port()
	tcfg := &tls.Config{ServerName: host, RootCAs: cfg.RootCAs, InsecureSkipVerify: cfg.Insecure, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{Timeout: timeout}
	var nc net.Conn
	switch strings.ToLower(u.Scheme) {
	case "ldaps":
		if port == "" {
			port = "636"
		}
		nc, err = tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), tcfg)
	case "ldap":
		if port == "" {
			port = "389"
		}
		nc, err = d.Dial("tcp", net.JoinHostPort(host, port))
	default:
		return nil, fmt.Errorf("ldap: unsupported scheme %q (use ldap:// or ldaps://)", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	c := &conn{c: nc, r: bufio.NewReader(nc), timeout: timeout}
	if cfg.StartTLS && strings.EqualFold(u.Scheme, "ldap") {
		if err := c.startTLS(tcfg); err != nil {
			nc.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *conn) close() {
	c.c.SetDeadline(time.Now().Add(2 * time.Second))
	c.id++
	c.c.Write(seq(tagSequence, encInt(tagInteger, c.id), tlv(opUnbindRequest, nil)))
	c.c.Close()
}

func (c *conn) send(op []byte) (int64, error) {
	c.id++
	c.c.SetDeadline(time.Now().Add(c.timeout))
	_, err := c.c.Write(seq(tagSequence, encInt(tagInteger, c.id), op))
	return c.id, err
}

func (c *conn) read(id int64) (element, error) {
	for {
		c.c.SetDeadline(time.Now().Add(c.timeout))
		m, err := readMessage(c.r, 16<<20)
		if err != nil {
			return element{}, err
		}
		if m.tag != tagSequence || len(m.children) < 2 {
			return element{}, errBER
		}
		if m.children[0].int() != id {
			continue
		}
		return m.children[1], nil
	}
}

func result(op element) error {
	if len(op.children) < 3 {
		return errBER
	}
	code := op.children[0].int()
	if code == resultSuccess {
		return nil
	}
	if code == resultInvalidCredentials {
		return ErrInvalidCredentials
	}
	return &Error{Code: code, Message: op.children[2].str()}
}

func (c *conn) startTLS(tcfg *tls.Config) error {
	id, err := c.send(seq(opExtendedRequest, encStr(0x80, startTLSOID)))
	if err != nil {
		return err
	}
	op, err := c.read(id)
	if err != nil {
		return err
	}
	if op.tag != opExtendedResponse {
		return errBER
	}
	if err := result(op); err != nil {
		return fmt.Errorf("ldap: StartTLS refused: %w", err)
	}
	tc := tls.Client(c.c, tcfg)
	tc.SetDeadline(time.Now().Add(c.timeout))
	if err := tc.Handshake(); err != nil {
		return err
	}
	c.c = tc
	c.r = bufio.NewReader(tc)
	return nil
}

func (c *conn) bind(dn, password string) error {
	id, err := c.send(seq(opBindRequest, encInt(tagInteger, 3), encStr(tagOctetString, dn), encStr(0x80, password)))
	if err != nil {
		return err
	}
	op, err := c.read(id)
	if err != nil {
		return err
	}
	if op.tag != opBindResponse {
		return errBER
	}
	return result(op)
}

func (c *conn) search(base string, scope int, filter string, attrs []string, limit int) ([]Entry, error) {
	f, err := compileFilter(filter)
	if err != nil {
		return nil, err
	}
	var al [][]byte
	for _, a := range attrs {
		if a != "" {
			al = append(al, encStr(tagOctetString, a))
		}
	}
	id, err := c.send(seq(opSearchRequest, encStr(tagOctetString, base), encInt(tagEnumerated, int64(scope)), encInt(tagEnumerated, 0),
		encInt(tagInteger, int64(limit)), encInt(tagInteger, int64(c.timeout/time.Second)), encBool(false), f, seq(tagSequence, al...)))
	if err != nil {
		return nil, err
	}
	var out []Entry
	for {
		op, err := c.read(id)
		if err != nil {
			return nil, err
		}
		switch op.tag {
		case opSearchEntry:
			if len(op.children) < 2 {
				return nil, errBER
			}
			e := Entry{DN: op.children[0].str(), Attrs: map[string][]string{}}
			for _, a := range op.children[1].children {
				if len(a.children) < 2 {
					continue
				}
				name := strings.ToLower(a.children[0].str())
				for _, v := range a.children[1].children {
					e.Attrs[name] = append(e.Attrs[name], v.str())
				}
			}
			out = append(out, e)
		case opSearchReference:
		case opSearchDone:
			if err := result(op); err != nil {
				var le *Error
				if errors.As(err, &le) && le.Code == 4 && len(out) > 0 {
					return out, nil
				}
				return nil, err
			}
			return out, nil
		default:
			return nil, errBER
		}
	}
}

func fill(template string, vars map[string]string) string {
	for k, v := range vars {
		template = strings.ReplaceAll(template, "{"+k+"}", v)
	}
	return template
}

func Authenticate(cfg Config, user, password string) (*Entry, error) {
	if strings.TrimSpace(user) == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	c, err := dial(cfg)
	if err != nil {
		return nil, err
	}
	defer c.close()
	attrs := append([]string{"memberOf", "cn", "displayName", "mail"}, cfg.Attributes...)
	filter := fill(firstNonEmpty(cfg.UserFilter, "(|(uid={user})(sAMAccountName={user})(userPrincipalName={user}))"), map[string]string{"user": EscapeFilter(user)})
	find := func() (*Entry, error) {
		list, err := c.search(cfg.BaseDN, ScopeSubtree, filter, attrs, 2)
		if err != nil {
			return nil, err
		}
		if len(list) != 1 {
			return nil, ErrUserNotFound
		}
		return &list[0], nil
	}
	var entry *Entry
	switch {
	case cfg.UserDN != "":
		dn := fill(cfg.UserDN, map[string]string{"user": EscapeDN(user)})
		if err := c.bind(dn, password); err != nil {
			return nil, err
		}
		if cfg.BaseDN != "" {
			entry, err = find()
		} else {
			var list []Entry
			list, err = c.search(dn, ScopeBase, "(objectClass=*)", attrs, 1)
			if err == nil && len(list) == 1 {
				entry = &list[0]
			} else if err == nil {
				err = ErrUserNotFound
			}
		}
		if err != nil {
			return nil, err
		}
	default:
		if cfg.BindDN != "" {
			if err := c.bind(cfg.BindDN, cfg.BindPassword); err != nil {
				return nil, fmt.Errorf("ldap: service account sign-in failed: %w", err)
			}
		}
		if entry, err = find(); err != nil {
			return nil, err
		}
		if err := c.bind(entry.DN, password); err != nil {
			return nil, err
		}
	}
	if cfg.GroupFilter != "" {
		if cfg.BindDN != "" && cfg.UserDN == "" {
			if err := c.bind(cfg.BindDN, cfg.BindPassword); err != nil {
				return nil, err
			}
		}
		gf := fill(cfg.GroupFilter, map[string]string{"dn": EscapeFilter(entry.DN), "user": EscapeFilter(user)})
		groups, err := c.search(firstNonEmpty(cfg.GroupBaseDN, cfg.BaseDN), ScopeSubtree, gf, []string{"cn"}, 1000)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			entry.Groups = append(entry.Groups, g.DN)
		}
	} else {
		entry.Groups = append(entry.Groups, entry.Get("memberOf")...)
	}
	return entry, nil
}

func CommonName(dn string) string {
	first := dn
	for j := 0; j < len(dn); j++ {
		if dn[j] == '\\' {
			j++
			continue
		}
		if dn[j] == ',' {
			first = dn[:j]
			break
		}
	}
	k, v, ok := strings.Cut(first, "=")
	if !ok {
		return strings.TrimSpace(dn)
	}
	if strings.EqualFold(strings.TrimSpace(k), "cn") || strings.EqualFold(strings.TrimSpace(k), "ou") {
		return strings.ReplaceAll(strings.TrimSpace(v), `\`, "")
	}
	return strings.TrimSpace(dn)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
