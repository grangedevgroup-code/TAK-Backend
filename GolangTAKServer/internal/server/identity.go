package server

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

const (
	DirIn  = "IN"
	DirOut = "OUT"
)

var (
	ErrNoUser      = errors.New("no such user")
	ErrUserExists  = errors.New("user already exists")
	ErrBadName     = errors.New("names may use letters, digits, '.', '_' and '-' (1-64 characters)")
	ErrBadPassword = errors.New("password must be at least 8 characters")
	ErrNoGroup     = errors.New("no such group")
	ErrThrottled   = errors.New("too many failed sign-in attempts; try again later")
)

var validName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

var validGroup = regexp.MustCompile(`^[A-Za-z0-9 ._:@()-]{1,64}$`)

type CertRecord struct {
	Serial    string    `json:"serial"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	ClientUID string    `json:"clientUid,omitempty"`
	Source    string    `json:"source"`
	Revoked   bool      `json:"revoked,omitempty"`
	RevokedAt time.Time `json:"revokedAt,omitempty"`
	Hash      string    `json:"hash,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	DER       []byte    `json:"der,omitempty"`
}

func newCertRecord(cert *x509.Certificate, clientUID, source string) CertRecord {
	sum := sha256.Sum256(cert.Raw)
	return CertRecord{Serial: pki.SerialHex(cert), Created: time.Now().UTC(), Expires: cert.NotAfter, ClientUID: clientUID, Source: source, Hash: hex.EncodeToString(sum[:]), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), DER: cert.Raw}
}

type User struct {
	Name      string       `json:"name"`
	Hash      string       `json:"hash,omitempty"`
	Admin     bool         `json:"admin"`
	Disabled  bool         `json:"disabled,omitempty"`
	In        []string     `json:"in"`
	Out       []string     `json:"out"`
	Inactive  []string     `json:"inactive,omitempty"`
	Callsign  string       `json:"callsign,omitempty"`
	Team      string       `json:"team,omitempty"`
	TeamRole  string       `json:"teamRole,omitempty"`
	Note      string       `json:"note,omitempty"`
	Created   time.Time    `json:"created"`
	LastLogin time.Time    `json:"lastLogin,omitempty"`
	Certs     []CertRecord `json:"certs,omitempty"`
	External  bool         `json:"external,omitempty"`
	Link      bool         `json:"link,omitempty"`
	Email     string       `json:"email,omitempty"`
	TwoFactor string       `json:"twoFactor,omitempty"`
	TOTP      string       `json:"totp,omitempty"`
	Recovery  []string     `json:"recovery,omitempty"`
	Pending   string       `json:"pending,omitempty"`
}

type Group struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Bit         int       `json:"bit"`
	Created     time.Time `json:"created"`
	System      bool      `json:"system,omitempty"`
}

type Token struct {
	ID       string    `json:"id"`
	Hash     string    `json:"hash"`
	User     string    `json:"user"`
	Kind     string    `json:"kind"`
	Name     string    `json:"name,omitempty"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitempty"`
	MaxUses  int       `json:"maxUses,omitempty"`
	Uses     int       `json:"uses,omitempty"`
	LastUsed time.Time `json:"lastUsed,omitempty"`
}

type Revoked struct {
	Serial string    `json:"serial"`
	User   string    `json:"user"`
	Time   time.Time `json:"time"`
}

type GroupMask []uint64

func (m GroupMask) Has(bit int) bool {
	i := bit / 64
	return i < len(m) && m[i]&(1<<uint(bit%64)) != 0
}

func (m *GroupMask) Set(bit int) {
	i := bit / 64
	for len(*m) <= i {
		*m = append(*m, 0)
	}
	(*m)[i] |= 1 << uint(bit%64)
}

func (m GroupMask) Intersects(o GroupMask) bool {
	n := min(len(m), len(o))
	for i := 0; i < n; i++ {
		if m[i]&o[i] != 0 {
			return true
		}
	}
	return false
}

func (m GroupMask) Empty() bool {
	for _, w := range m {
		if w != 0 {
			return false
		}
	}
	return true
}

func (m GroupMask) Count() int {
	c := 0
	for _, w := range m {
		c += bits.OnesCount64(w)
	}
	return c
}

func (m GroupMask) Union(o GroupMask) GroupMask {
	out := append(GroupMask(nil), m...)
	for i, w := range o {
		if i < len(out) {
			out[i] |= w
		} else {
			out = append(out, w)
		}
	}
	return out
}

type Identity struct {
	Name    string
	Admin   bool
	Via     string
	In      GroupMask
	Out     GroupMask
	Cert    *x509.Certificate
	Anon    bool
	TokenID string
	Link    bool
}

type Session struct {
	ID      string
	User    string
	Admin   bool
	Expires time.Time
	CSRF    string
}

type verifyEntry struct {
	digest  [32]byte
	expires time.Time
}

type Directory struct {
	users    *store.Collection[User]
	groups   *store.Collection[Group]
	tokens   *store.Collection[Token]
	revoked  *store.Collection[Revoked]
	anon     string
	mu       sync.RWMutex
	bits     map[string]int
	names    map[int]string
	revSet   map[string]bool
	vmu      sync.Mutex
	verified map[string]verifyEntry
	smu      sync.Mutex
	sessions map[string]*Session
	limiter  *limiter
	OnChange func(user string)
	External func(name, password string) (*ExternalAuth, error)
}

type ExternalAuth struct {
	Groups   []string
	Admin    bool
	Callsign string
}

func OpenDirectory(dir, anonGroup string) (*Directory, error) {
	d := &Directory{anon: anonGroup, bits: map[string]int{}, names: map[int]string{}, revSet: map[string]bool{},
		verified: map[string]verifyEntry{}, sessions: map[string]*Session{}, limiter: newLimiter(10, 10*time.Minute)}
	var err error
	if d.users, err = store.Open[User](filepath.Join(dir, "users.jsonl"), true); err != nil {
		return nil, err
	}
	if d.groups, err = store.Open[Group](filepath.Join(dir, "groups.jsonl"), true); err != nil {
		return nil, err
	}
	if d.tokens, err = store.Open[Token](filepath.Join(dir, "tokens.jsonl"), true); err != nil {
		return nil, err
	}
	if d.revoked, err = store.Open[Revoked](filepath.Join(dir, "revoked.jsonl"), true); err != nil {
		return nil, err
	}
	for _, g := range d.groups.All() {
		d.bits[g.Name] = g.Bit
		d.names[g.Bit] = g.Name
	}
	for _, r := range d.revoked.All() {
		d.revSet[strings.ToLower(r.Serial)] = true
	}
	if _, err := d.EnsureGroup(anonGroup, "Default group for anonymous and new users", true); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Directory) Close() {
	d.users.Close()
	d.groups.Close()
	d.tokens.Close()
	d.revoked.Close()
}

func (d *Directory) EnsureGroup(name, desc string, system bool) (Group, error) {
	name = strings.TrimSpace(name)
	if !validGroup.MatchString(name) {
		return Group{}, fmt.Errorf("invalid group name %q", name)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if g, ok := d.groups.Get(name); ok {
		return g, nil
	}
	bit := 0
	for {
		if _, used := d.names[bit]; !used {
			break
		}
		bit++
	}
	g := Group{Name: name, Description: desc, Bit: bit, Created: time.Now().UTC(), System: system}
	if err := d.groups.Put(name, g); err != nil {
		return Group{}, err
	}
	d.bits[name] = bit
	d.names[bit] = name
	return g, nil
}

func (d *Directory) Groups() []Group {
	gs := d.groups.All()
	sort.Slice(gs, func(i, j int) bool { return gs[i].Bit < gs[j].Bit })
	return gs
}

func (d *Directory) Group(name string) (Group, bool) { return d.groups.Get(name) }

func (d *Directory) DeleteGroup(name string) error {
	g, ok := d.groups.Get(name)
	if !ok {
		return ErrNoGroup
	}
	if g.System || name == d.anon {
		return errors.New("the default group cannot be deleted")
	}
	for _, u := range d.users.All() {
		if slices.Contains(u.In, name) || slices.Contains(u.Out, name) {
			d.UpdateUser(u.Name, func(x *User) error {
				x.In = slices.DeleteFunc(x.In, func(s string) bool { return s == name })
				x.Out = slices.DeleteFunc(x.Out, func(s string) bool { return s == name })
				return nil
			})
		}
	}
	d.mu.Lock()
	delete(d.bits, name)
	delete(d.names, g.Bit)
	d.mu.Unlock()
	return d.groups.Delete(name)
}

func (d *Directory) Mask(names []string) GroupMask {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var m GroupMask
	for _, n := range names {
		if b, ok := d.bits[n]; ok {
			m.Set(b)
		}
	}
	return m
}

func (d *Directory) Names(m GroupMask) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []string
	for i, w := range m {
		for w != 0 {
			b := bits.TrailingZeros64(w)
			w &^= 1 << uint(b)
			if n, ok := d.names[i*64+b]; ok {
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (d *Directory) AnonGroup() string { return d.anon }

func (d *Directory) Anonymous() *Identity {
	m := d.Mask([]string{d.anon})
	return &Identity{Via: "anonymous", In: m, Out: m, Anon: true}
}

func activeList(all []string, inactive []string, dir string) []string {
	var out []string
	for _, g := range all {
		if !slices.Contains(inactive, g+"|"+dir) {
			out = append(out, g)
		}
	}
	return out
}

func (d *Directory) identityFor(u User, via string) *Identity {
	in := activeList(u.In, u.Inactive, DirIn)
	out := activeList(u.Out, u.Inactive, DirOut)
	return &Identity{Name: u.Name, Admin: u.Admin, Via: via, In: d.Mask(in), Out: d.Mask(out), Link: u.Link}
}

func (d *Directory) Identity(name, via string) (*Identity, error) {
	u, ok := d.users.Get(name)
	if !ok {
		return nil, ErrNoUser
	}
	if u.Disabled {
		return nil, errors.New("account disabled")
	}
	return d.identityFor(u, via), nil
}

func (d *Directory) User(name string) (User, bool) { return d.users.Get(name) }

func (d *Directory) Users() []User { return d.users.All() }

func (d *Directory) UserCount() int { return d.users.Len() }

const hashIterations = 120000

func HashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	k, _ := pbkdf2.Key(sha256.New, pw, salt, hashIterations, 32)
	return "pbkdf2-sha256$" + strconv.Itoa(hashIterations) + "$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(k)
}

func checkHash(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func ValidUserName(name string) bool { return validName.MatchString(name) }

func (d *Directory) AddUser(name, password string, admin bool, groups []string) (User, error) {
	if !validName.MatchString(name) {
		return User{}, ErrBadName
	}
	if len(password) < 8 {
		return User{}, ErrBadPassword
	}
	if len(groups) == 0 {
		groups = []string{d.anon}
	}
	if err := d.ensureGroups(groups); err != nil {
		return User{}, err
	}
	u := User{Name: name, Hash: HashPassword(password), Admin: admin, In: uniqueSorted(groups), Out: uniqueSorted(groups), Created: time.Now().UTC()}
	_, err := d.users.Update(name, func(cur User, exists bool) (User, bool, error) {
		if exists {
			return cur, true, ErrUserExists
		}
		return u, true, nil
	})
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func (d *Directory) EnsureExternalUser(name string) User {
	if u, ok := d.users.Get(name); ok {
		return u
	}
	u := User{Name: name, In: []string{d.anon}, Out: []string{d.anon}, Created: time.Now().UTC(), External: true}
	d.users.Update(name, func(cur User, exists bool) (User, bool, error) {
		if exists {
			u = cur
			return cur, true, nil
		}
		return u, true, nil
	})
	return u
}

func (d *Directory) UpdateUser(name string, fn func(u *User) error) (User, error) {
	u, err := d.users.Update(name, func(cur User, exists bool) (User, bool, error) {
		if !exists {
			return cur, false, ErrNoUser
		}
		if err := fn(&cur); err != nil {
			return cur, true, err
		}
		return cur, true, nil
	})
	if err == nil {
		d.forget(name)
		if d.OnChange != nil {
			d.OnChange(name)
		}
	}
	return u, err
}

func (d *Directory) SetPassword(name, password string) error {
	if len(password) < 8 {
		return ErrBadPassword
	}
	_, err := d.UpdateUser(name, func(u *User) error {
		u.Hash = HashPassword(password)
		return nil
	})
	d.vmu.Lock()
	delete(d.verified, name)
	d.vmu.Unlock()
	return err
}

func (d *Directory) EndUserSessions(user string) { d.EndSessions(user) }

func (d *Directory) ensureGroups(names []string) error {
	for _, g := range names {
		if _, err := d.EnsureGroup(g, "", false); err != nil {
			return err
		}
	}
	return nil
}

func (d *Directory) SetGroups(name string, in, out []string) error {
	if _, ok := d.users.Get(name); !ok {
		return ErrNoUser
	}
	if err := d.ensureGroups(append(append([]string(nil), in...), out...)); err != nil {
		return err
	}
	_, err := d.UpdateUser(name, func(u *User) error {
		u.In = uniqueSorted(in)
		u.Out = uniqueSorted(out)
		return nil
	})
	return err
}

func uniqueSorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return slices.Compact(out)
}

func (d *Directory) DeleteUser(name string) (int, error) {
	u, ok := d.users.Get(name)
	if !ok {
		return 0, ErrNoUser
	}
	n := 0
	for _, c := range u.Certs {
		if !c.Revoked {
			d.revoke(c.Serial, name)
			n++
		}
	}
	for _, t := range d.tokens.All() {
		if t.User == name {
			d.tokens.Delete(t.ID)
		}
	}
	d.forget(name)
	d.EndSessions(name)
	err := d.users.Delete(name)
	if d.OnChange != nil {
		d.OnChange(name)
	}
	return n, err
}

func (d *Directory) revoke(serial, user string) {
	serial = strings.ToLower(serial)
	d.revoked.Put(serial, Revoked{Serial: serial, User: user, Time: time.Now().UTC()})
	d.mu.Lock()
	d.revSet[serial] = true
	d.mu.Unlock()
}

func (d *Directory) RevokeCert(serial string) error {
	serial = strings.ToLower(serial)
	owner := ""
	for _, u := range d.users.All() {
		for _, c := range u.Certs {
			if strings.EqualFold(c.Serial, serial) {
				owner = u.Name
			}
		}
	}
	if owner != "" {
		d.UpdateUser(owner, func(u *User) error {
			for i := range u.Certs {
				if strings.EqualFold(u.Certs[i].Serial, serial) && !u.Certs[i].Revoked {
					u.Certs[i].Revoked = true
					u.Certs[i].RevokedAt = time.Now().UTC()
				}
			}
			return nil
		})
	}
	d.revoke(serial, owner)
	return nil
}

func (d *Directory) RevokeAll(user string) int {
	n := 0
	u, ok := d.users.Get(user)
	if !ok {
		return 0
	}
	for _, c := range u.Certs {
		if !c.Revoked {
			d.revoke(c.Serial, user)
			n++
		}
	}
	d.UpdateUser(user, func(u *User) error {
		for i := range u.Certs {
			if !u.Certs[i].Revoked {
				u.Certs[i].Revoked = true
				u.Certs[i].RevokedAt = time.Now().UTC()
			}
		}
		return nil
	})
	return n
}

func (d *Directory) IsRevoked(serial string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.revSet[strings.ToLower(serial)]
}

func (d *Directory) RecordCert(user string, rec CertRecord) error {
	_, err := d.users.Update(user, func(u User, exists bool) (User, bool, error) {
		if !exists {
			return u, false, ErrNoUser
		}
		u.Certs = append(u.Certs, rec)
		if len(u.Certs) > 50 {
			var keep []CertRecord
			for _, c := range u.Certs {
				if !c.Revoked || time.Since(c.Created) < 365*24*time.Hour {
					keep = append(keep, c)
				}
			}
			u.Certs = keep
		}
		return u, true, nil
	})
	return err
}

func (d *Directory) forget(name string) {
	d.vmu.Lock()
	delete(d.verified, name)
	d.vmu.Unlock()
}

var verifyKey = func() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}()

func digest(name, pw string) [32]byte {
	m := hmac.New(sha256.New, verifyKey)
	m.Write([]byte(name))
	m.Write([]byte{0})
	m.Write([]byte(pw))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (d *Directory) CheckPassword(ip, name, pw string) (*Identity, error) {
	if d.limiter.blocked(ip) {
		return nil, ErrThrottled
	}
	u, ok := d.users.Get(name)
	if ok && !u.Disabled {
		dg := digest(name, pw)
		d.vmu.Lock()
		e, cached := d.verified[name]
		d.vmu.Unlock()
		if cached && time.Now().Before(e.expires) && subtle.ConstantTimeCompare(e.digest[:], dg[:]) == 1 {
			return d.identityFor(u, "password"), nil
		}
		if u.Hash != "" && checkHash(u.Hash, pw) {
			d.vmu.Lock()
			d.verified[name] = verifyEntry{digest: dg, expires: time.Now().Add(15 * time.Minute)}
			d.vmu.Unlock()
			if time.Since(u.LastLogin) > time.Hour {
				d.users.Update(name, func(x User, ok bool) (User, bool, error) {
					x.LastLogin = time.Now().UTC()
					return x, ok, nil
				})
			}
			return d.identityFor(u, "password"), nil
		}
		if id, err := d.useToken(pw, name, "enroll"); err == nil {
			return id, nil
		}
	} else if !ok {
		checkHash("pbkdf2-sha256$"+strconv.Itoa(hashIterations)+"$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pw)
	}
	if d.External != nil && (!ok || (!u.Disabled && (u.External || u.Hash == ""))) && validName.MatchString(name) {
		if res, err := d.External(name, pw); err == nil {
			if id, err := d.externalLogin(name, res); err == nil {
				d.vmu.Lock()
				d.verified[name] = verifyEntry{digest: digest(name, pw), expires: time.Now().Add(15 * time.Minute)}
				d.vmu.Unlock()
				return id, nil
			}
		}
	}
	d.limiter.fail(ip)
	return nil, errors.New("invalid user name or password")
}

func (d *Directory) externalLogin(name string, res *ExternalAuth) (*Identity, error) {
	groups := res.Groups
	if len(groups) == 0 {
		groups = []string{d.anon}
	}
	if err := d.ensureGroups(groups); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	u, err := d.users.Update(name, func(cur User, exists bool) (User, bool, error) {
		if exists && !cur.External && cur.Hash != "" {
			return cur, true, errors.New("a local account with this name exists")
		}
		if !exists {
			cur = User{Name: name, Created: now}
		}
		cur.External = true
		cur.In = uniqueSorted(groups)
		cur.Out = uniqueSorted(groups)
		cur.Admin = res.Admin
		if res.Callsign != "" {
			cur.Callsign = res.Callsign
		}
		cur.LastLogin = now
		return cur, true, nil
	})
	if err != nil {
		return nil, err
	}
	d.forget(name)
	if d.OnChange != nil {
		d.OnChange(name)
	}
	return d.identityFor(u, "ldap"), nil
}

func NewSecret(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (d *Directory) CreateToken(user, kind, name string, ttl time.Duration, maxUses int) (string, Token, error) {
	if _, ok := d.users.Get(user); !ok {
		return "", Token{}, ErrNoUser
	}
	secret := NewSecret(24)
	if kind == "enroll" {
		secret = FriendlySecret()
	}
	t := Token{ID: NewSecret(9), Hash: tokenHash(secret), User: user, Kind: kind, Name: name, Created: time.Now().UTC(), MaxUses: maxUses}
	if ttl > 0 {
		t.Expires = t.Created.Add(ttl)
	}
	if err := d.tokens.Put(t.ID, t); err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

func (d *Directory) Tokens() []Token { return d.tokens.All() }

func (d *Directory) DeleteToken(id string) error { return d.tokens.Delete(id) }

func (d *Directory) useToken(secret, user, kind string) (*Identity, error) {
	h := tokenHash(secret)
	for _, t := range d.tokens.All() {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) != 1 {
			continue
		}
		if (user != "" && t.User != user) || (kind != "" && t.Kind != kind) {
			return nil, errors.New("token not valid here")
		}
		if !t.Expires.IsZero() && time.Now().After(t.Expires) {
			d.tokens.Delete(t.ID)
			return nil, errors.New("token expired")
		}
		if t.MaxUses > 0 && t.Uses >= t.MaxUses {
			d.tokens.Delete(t.ID)
			return nil, errors.New("token already used")
		}
		u, ok := d.users.Get(t.User)
		if !ok || u.Disabled {
			return nil, ErrNoUser
		}
		if time.Since(t.LastUsed) > 5*time.Minute {
			d.tokens.Update(t.ID, func(x Token, ok bool) (Token, bool, error) {
				x.LastUsed = time.Now().UTC()
				return x, ok, nil
			})
		}
		id := d.identityFor(u, "token")
		id.TokenID = t.ID
		return id, nil
	}
	return nil, errors.New("invalid token")
}

func (d *Directory) ConsumeToken(id string) {
	d.tokens.Update(id, func(x Token, ok bool) (Token, bool, error) {
		if !ok {
			return x, false, nil
		}
		x.Uses++
		x.LastUsed = time.Now().UTC()
		if x.MaxUses > 0 && x.Uses >= x.MaxUses {
			return x, false, nil
		}
		return x, true, nil
	})
}

func (d *Directory) CheckToken(ip, secret string) (*Identity, error) {
	if d.limiter.blocked(ip) {
		return nil, ErrThrottled
	}
	id, err := d.useToken(secret, "", "api")
	if err != nil {
		d.limiter.fail(ip)
	}
	return id, err
}

func (d *Directory) NewSession(u User, ttl time.Duration) *Session {
	s := &Session{ID: NewSecret(32), User: u.Name, Admin: u.Admin, Expires: time.Now().Add(ttl), CSRF: NewSecret(18)}
	d.smu.Lock()
	for id, x := range d.sessions {
		if time.Now().After(x.Expires) {
			delete(d.sessions, id)
		}
	}
	d.sessions[s.ID] = s
	d.smu.Unlock()
	return s
}

func (d *Directory) SessionFor(id string) (*Session, bool) {
	d.smu.Lock()
	defer d.smu.Unlock()
	s, ok := d.sessions[id]
	if !ok || time.Now().After(s.Expires) {
		delete(d.sessions, id)
		return nil, false
	}
	return s, true
}

func (d *Directory) EndSession(id string) {
	d.smu.Lock()
	delete(d.sessions, id)
	d.smu.Unlock()
}

func (d *Directory) EndSessions(user string) {
	d.smu.Lock()
	for id, s := range d.sessions {
		if s.User == user {
			delete(d.sessions, id)
		}
	}
	d.smu.Unlock()
}

func (d *Directory) SetActive(user string, changes map[string]bool) error {
	_, err := d.UpdateUser(user, func(u *User) error {
		for key, active := range changes {
			u.Inactive = slices.DeleteFunc(u.Inactive, func(s string) bool { return s == key })
			if !active {
				u.Inactive = append(u.Inactive, key)
			}
		}
		sort.Strings(u.Inactive)
		return nil
	})
	return err
}

func FriendlySecret() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	rand.Read(b)
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func limiterKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil || p.To4() != nil {
		return ip
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (l *limiter) blocked(ip string) bool {
	if ip == "" {
		return false
	}
	ip = limiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-l.window)
	h := l.hits[ip]
	k := 0
	for _, t := range h {
		if t.After(cut) {
			h[k] = t
			k++
		}
	}
	if k == 0 {
		delete(l.hits, ip)
		return false
	}
	l.hits[ip] = h[:k]
	return k >= l.max
}

func (l *limiter) fail(ip string) {
	if ip == "" {
		return
	}
	ip = limiterKey(ip)
	l.mu.Lock()
	if len(l.hits) > 50000 {
		cut := time.Now().Add(-l.window)
		for k, h := range l.hits {
			if len(h) == 0 || !h[len(h)-1].After(cut) {
				delete(l.hits, k)
			}
		}
	}
	if len(l.hits) <= 200000 || l.hits[ip] != nil {
		l.hits[ip] = append(l.hits[ip], time.Now())
	}
	l.mu.Unlock()
}
