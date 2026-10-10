package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type EmailConfig struct {
	Enabled              bool     `json:"enabled"`
	Host                 string   `json:"host"`
	Port                 int      `json:"port"`
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	From                 string   `json:"from"`
	Security             string   `json:"security"`
	PublicURL            string   `json:"publicUrl"`
	AllowRegistration    bool     `json:"allowRegistration"`
	ApproveRegistrations bool     `json:"approveRegistrations"`
	AllowedDomains       []string `json:"allowedDomains"`
	BlockedDomains       []string `json:"blockedDomains"`
	RegistrationGroups   []string `json:"registrationGroups"`
}

type authToken struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	User    string    `json:"user"`
	Expires time.Time `json:"expires"`
}

type loginChallenge struct {
	user    string
	method  string
	code    string
	expires time.Time
	tries   int
}

type accountSecurity struct {
	tokens     *store.Collection[authToken]
	mu         sync.Mutex
	challenges map[string]*loginChallenge
	lastStep   map[string]int64
	pending    map[string]string
}

var (
	authLimiter    = newLimiter(20, 15*time.Minute)
	errBadCode     = errors.New("that code is not correct")
	errEmailOff    = errors.New("email is not set up on this server")
	errLinkExpired = errors.New("this link has expired or was already used")
)

func openAccountSecurity(dataDir string) (*accountSecurity, error) {
	db, err := store.Open[authToken](filepath.Join(dataDir, "db", "auth-tokens.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &accountSecurity{tokens: db, challenges: map[string]*loginChallenge{}, lastStep: map[string]int64{}, pending: map[string]string{}}, nil
}

func (a *accountSecurity) Close() { a.tokens.Close() }

func (a *accountSecurity) issue(kind, user string, ttl time.Duration) string {
	t := NewSecret(32)
	for _, old := range a.tokens.All() {
		if time.Now().After(old.Expires) || (old.Kind == kind && old.User == user) {
			a.tokens.Delete(old.ID)
		}
	}
	id := tokenHash(t)
	a.tokens.Put(id, authToken{ID: id, Kind: kind, User: user, Expires: time.Now().Add(ttl)})
	return t
}

func (a *accountSecurity) redeem(kind, t string) (string, bool) {
	id := tokenHash(strings.TrimSpace(t))
	tok, ok := a.tokens.Get(id)
	if !ok || tok.Kind != kind || time.Now().After(tok.Expires) {
		return "", false
	}
	a.tokens.Delete(id)
	return tok.User, true
}

func newTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func totpAt(secret string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

func (a *accountSecurity) checkTOTP(user, secret, code string) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		want, err := totpAt(secret, now+d)
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.lastStep[user] >= now+d {
				return false
			}
			a.lastStep[user] = now + d
			return true
		}
	}
	return false
}

func sixDigits() string {
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(b[:])%1000000)
}

func (s *Server) sendMail(to, subject, body string) error {
	ec := s.Config().Email
	if !ec.Enabled || ec.Host == "" || ec.From == "" {
		return errEmailOff
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("bad email address: %w", err)
	}
	from, err := mail.ParseAddress(ec.From)
	if err != nil {
		return fmt.Errorf("bad sender address: %w", err)
	}
	port := ec.Port
	if port == 0 {
		port = 587
		if ec.Security == "tls" {
			port = 465
		}
	}
	addr := net.JoinHostPort(ec.Host, strconv.Itoa(port))
	tcfg := &tls.Config{ServerName: ec.Host, MinVersion: tls.VersionTLS12}
	var c *smtp.Client
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	if ec.Security == "tls" {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tcfg)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, ec.Host); err != nil {
			conn.Close()
			return err
		}
	} else {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return err
		}
		conn.SetDeadline(time.Now().Add(time.Minute))
		if c, err = smtp.NewClient(conn, ec.Host); err != nil {
			conn.Close()
			return err
		}
		if ec.Security != "none" {
			if ok, _ := c.Extension("STARTTLS"); !ok {
				c.Close()
				return errors.New("the mail server does not offer STARTTLS; set security to tls or none")
			}
			if err := c.StartTLS(tcfg); err != nil {
				c.Close()
				return err
			}
		}
	}
	defer c.Close()
	if ec.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", ec.Username, ec.Password, ec.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	clean := func(v string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(v) }
	msg := "From: " + clean(from.String()) + "\r\nTo: " + clean(to) + "\r\nSubject: " + mimeHeader(clean(subject)) + "\r\nDate: " + time.Now().Format(time.RFC1123Z) +
		"\r\nMessage-ID: <" + NewSecret(12) + "@" + clean(ec.Host) + ">\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n") + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func mimeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?utf-8?q?" + strings.NewReplacer("=", "=3D", "?", "=3F", "_", "=5F", " ", "_").Replace(s) + "?="
		}
	}
	return s
}

func (s *Server) publicBase(r *http.Request) string {
	if u := strings.TrimRight(s.Config().Email.PublicURL, "/"); u != "" {
		return u
	}
	return s.baseURL(r)
}

func domainAllowed(ec EmailConfig, addr string) bool {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return false
	}
	dom := strings.ToLower(addr[at+1:])
	match := func(rule string) bool {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if rule == "" {
			return false
		}
		if strings.HasPrefix(rule, ".") {
			return strings.HasSuffix(dom, rule)
		}
		return dom == rule || strings.HasSuffix(dom, "."+rule)
	}
	for _, b := range ec.BlockedDomains {
		if match(b) {
			return false
		}
	}
	if len(ec.AllowedDomains) == 0 {
		return true
	}
	for _, a := range ec.AllowedDomains {
		if match(a) {
			return true
		}
	}
	return false
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, u User) bool {
	if u.TwoFactor == "" {
		return false
	}
	ch := &loginChallenge{user: u.Name, method: u.TwoFactor, expires: time.Now().Add(5 * time.Minute)}
	if u.TwoFactor == "email" {
		ch.code = sixDigits()
		if err := s.sendMail(u.Email, "Your "+s.Config().Name+" sign-in code", "Your sign-in code is "+ch.code+".\n\nIt expires in 5 minutes. If you did not try to sign in, change your password."); err != nil {
			s.log.Error("sign-in code could not be emailed", "user", u.Name, "err", err)
			apiError(w, http.StatusServiceUnavailable, errors.New("the sign-in code could not be emailed; ask an administrator"))
			return true
		}
	}
	id := NewSecret(24)
	s.acct.mu.Lock()
	for k, c := range s.acct.challenges {
		if time.Now().After(c.expires) {
			delete(s.acct.challenges, k)
		}
	}
	s.acct.challenges[id] = ch
	s.acct.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"twoFactor": u.TwoFactor, "challenge": id})
	return true
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, u User) {
	sess := s.dir.NewSession(u, 12*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 12 * 3600}) // #nosec G124 nosemgrep -- Secure whenever the request arrived over TLS; plain HTTP is a LAN option
	s.log.Info("dashboard sign-in", "user", u.Name, "remote", requestIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"user": u.Name, "admin": u.Admin, "csrf": sess.CSRF})
}

func (s *Server) apiLoginVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	ip := requestIP(r)
	if authLimiter.blocked(ip) {
		apiError(w, http.StatusTooManyRequests, ErrThrottled)
		return
	}
	s.acct.mu.Lock()
	ch, ok := s.acct.challenges[body.Challenge]
	if ok && time.Now().After(ch.expires) {
		delete(s.acct.challenges, body.Challenge)
		ok = false
	}
	s.acct.mu.Unlock()
	if !ok {
		apiError(w, http.StatusUnauthorized, errors.New("the sign-in expired; start again"))
		return
	}
	u, exists := s.dir.User(ch.user)
	if !exists || u.Disabled {
		apiError(w, http.StatusUnauthorized, errors.New("the account is not available"))
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(body.Code), " ", "")
	good := false
	switch ch.method {
	case "totp":
		good = s.acct.checkTOTP(u.Name, u.TOTP, code)
	case "email":
		good = len(code) == 6 && subtle.ConstantTimeCompare([]byte(code), []byte(ch.code)) == 1
	}
	if !good && len(code) > 6 {
		good = s.useRecoveryCode(u.Name, code)
	}
	if !good {
		authLimiter.fail(ip)
		s.acct.mu.Lock()
		ch.tries++
		if ch.tries >= 5 {
			delete(s.acct.challenges, body.Challenge)
		}
		s.acct.mu.Unlock()
		s.log.Warn("two-factor code rejected", "user", u.Name, "remote", ip)
		apiError(w, http.StatusUnauthorized, errBadCode)
		return
	}
	s.acct.mu.Lock()
	delete(s.acct.challenges, body.Challenge)
	s.acct.mu.Unlock()
	s.finishLogin(w, r, u)
}

func (s *Server) useRecoveryCode(user, code string) bool {
	h := tokenHash(strings.ToLower(code))
	used := false
	s.dir.UpdateUser(user, func(u *User) error {
		for i, c := range u.Recovery {
			if subtle.ConstantTimeCompare([]byte(c), []byte(h)) == 1 {
				u.Recovery = append(u.Recovery[:i], u.Recovery[i+1:]...)
				used = true
				return nil
			}
		}
		return nil
	})
	if used {
		s.log.Warn("recovery code used for sign-in", "user", user)
	}
	return used
}

func (s *Server) apiAuthOptions(w http.ResponseWriter, r *http.Request) {
	ec := s.Config().Email
	on := ec.Enabled && ec.Host != ""
	writeJSON(w, http.StatusOK, map[string]bool{"registration": on && ec.AllowRegistration, "passwordReset": on})
}

func (s *Server) apiAccount(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	u, ok := s.dir.User(id.Name)
	if !ok {
		apiError(w, http.StatusNotFound, ErrNoUser)
		return
	}
	ec := s.Config().Email
	writeJSON(w, http.StatusOK, map[string]any{"name": u.Name, "email": u.Email, "twoFactor": u.TwoFactor, "recoveryCodes": len(u.Recovery), "emailEnabled": ec.Enabled && ec.Host != ""})
}

func (s *Server) apiAccountEmail(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := s.dir.CheckPassword(requestIP(r), id.Name, body.Password); err != nil {
		apiError(w, http.StatusForbidden, errors.New("the password is not correct"))
		return
	}
	addr := strings.TrimSpace(body.Email)
	if addr != "" {
		if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
			apiError(w, http.StatusBadRequest, errors.New("that is not a valid email address"))
			return
		}
	}
	s.dir.UpdateUser(id.Name, func(u *User) error {
		u.Email = addr
		if addr == "" && u.TwoFactor == "email" {
			u.TwoFactor = ""
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiTOTPSetup(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	secret := newTOTPSecret()
	s.acct.mu.Lock()
	s.acct.pending[id.Name] = secret
	s.acct.mu.Unlock()
	uri := "otpauth://totp/" + url.PathEscape(s.Config().Name+":"+id.Name) + "?secret=" + secret + "&issuer=" + url.QueryEscape(s.Config().Name) + "&algorithm=SHA1&digits=6&period=30"
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": uri, "qr": qrSVG(uri)})
}

func (s *Server) apiTwoFactorEnable(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Method string `json:"method"`
		Code   string `json:"code"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	u, _ := s.dir.User(id.Name)
	var secret string
	switch body.Method {
	case "totp":
		s.acct.mu.Lock()
		secret = s.acct.pending[id.Name]
		s.acct.mu.Unlock()
		if secret == "" || !s.acct.checkTOTP(id.Name, secret, body.Code) {
			apiError(w, http.StatusBadRequest, errBadCode)
			return
		}
	case "email":
		if u.Email == "" {
			apiError(w, http.StatusBadRequest, errors.New("add an email address first"))
			return
		}
		s.acct.mu.Lock()
		want := s.acct.pending["email:"+id.Name]
		s.acct.mu.Unlock()
		if body.Code == "" {
			code := sixDigits()
			if err := s.sendMail(u.Email, "Confirm two-factor sign-in", "Your confirmation code is "+code+"."); err != nil {
				apiError(w, http.StatusServiceUnavailable, err)
				return
			}
			s.acct.mu.Lock()
			s.acct.pending["email:"+id.Name] = code
			s.acct.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]bool{"codeSent": true})
			return
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(body.Code))) != 1 {
			apiError(w, http.StatusBadRequest, errBadCode)
			return
		}
	default:
		apiError(w, http.StatusBadRequest, errors.New("method must be totp or email"))
		return
	}
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		raw := strings.ToLower(NewSecret(9))
		codes[i] = raw[:5] + "-" + raw[5:10]
		hashes[i] = tokenHash(codes[i])
	}
	s.dir.UpdateUser(id.Name, func(u *User) error {
		u.TwoFactor = body.Method
		u.TOTP = secret
		u.Recovery = hashes
		return nil
	})
	s.acct.mu.Lock()
	delete(s.acct.pending, id.Name)
	delete(s.acct.pending, "email:"+id.Name)
	s.acct.mu.Unlock()
	s.log.Info("two-factor sign-in turned on", "user", id.Name, "method", body.Method)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

func (s *Server) apiTwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Password string `json:"password"`
	}
	decodeBody(r, &body)
	if _, err := s.dir.CheckPassword(requestIP(r), id.Name, body.Password); err != nil {
		apiError(w, http.StatusForbidden, errors.New("the password is not correct"))
		return
	}
	s.clearTwoFactor(id.Name)
	s.log.Info("two-factor sign-in turned off", "user", id.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) clearTwoFactor(name string) {
	s.dir.UpdateUser(name, func(u *User) error {
		u.TwoFactor, u.TOTP, u.Recovery = "", "", nil
		return nil
	})
}

func (s *Server) apiUserReset2FA(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, ok := s.dir.User(name); !ok {
		apiError(w, http.StatusNotFound, ErrNoUser)
		return
	}
	s.clearTwoFactor(name)
	s.log.Info("two-factor sign-in reset by an administrator", "user", name, "by", identityOf(r).Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiPasswordForgot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Login string `json:"login"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	ip := requestIP(r)
	if authLimiter.blocked(ip) {
		apiError(w, http.StatusTooManyRequests, ErrThrottled)
		return
	}
	authLimiter.fail(ip)
	login := strings.TrimSpace(body.Login)
	var target *User
	for _, u := range s.dir.Users() {
		if !u.External && !u.Disabled && u.Email != "" && (strings.EqualFold(u.Name, login) || strings.EqualFold(u.Email, login)) {
			cp := u
			target = &cp
			break
		}
	}
	if target != nil {
		tok := s.acct.issue("reset", target.Name, time.Hour)
		link := s.publicBase(r) + "/#/reset/" + tok
		go func(u User) {
			if err := s.sendMail(u.Email, "Reset your "+s.Config().Name+" password", "Someone asked to reset the password for "+u.Name+".\n\nOpen this link within an hour to choose a new password:\n"+link+"\n\nIf it was not you, ignore this message."); err != nil {
				s.log.Error("password reset email failed", "user", u.Name, "err", err)
			}
		}(*target)
		s.log.Info("password reset requested", "user", target.Name, "remote", ip)
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "If an account with that name or email exists, a reset link is on its way."})
}

func (s *Server) apiPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if len(body.Password) < 8 {
		apiError(w, http.StatusBadRequest, ErrBadPassword)
		return
	}
	user, ok := s.acct.redeem("reset", body.Token)
	if !ok {
		apiError(w, http.StatusBadRequest, errLinkExpired)
		return
	}
	if err := s.dir.SetPassword(user, body.Password); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.dir.EndUserSessions(user)
	s.forgetInitialPassword(user)
	s.log.Info("password reset by email link", "user", user, "remote", requestIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiRegister(w http.ResponseWriter, r *http.Request) {
	ec := s.Config().Email
	if !ec.Enabled || !ec.AllowRegistration || ec.Host == "" {
		apiError(w, http.StatusNotFound, errors.New("registration is not open on this server"))
		return
	}
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	ip := requestIP(r)
	if authLimiter.blocked(ip) {
		apiError(w, http.StatusTooManyRequests, ErrThrottled)
		return
	}
	authLimiter.fail(ip)
	addr := strings.TrimSpace(body.Email)
	if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
		apiError(w, http.StatusBadRequest, errors.New("enter a valid email address"))
		return
	}
	if !domainAllowed(ec, addr) {
		apiError(w, http.StatusForbidden, errors.New("accounts cannot be created with that email address"))
		return
	}
	if strings.ContainsAny(body.Password, "@:") {
		apiError(w, http.StatusBadRequest, errors.New("passwords cannot contain @ or : because they break video and server links"))
		return
	}
	for _, u := range s.dir.Users() {
		if strings.EqualFold(u.Email, addr) {
			apiError(w, http.StatusConflict, errors.New("an account already uses that email address"))
			return
		}
	}
	if _, err := s.dir.AddUser(strings.TrimSpace(body.Username), body.Password, false, ec.RegistrationGroups); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	name := strings.TrimSpace(body.Username)
	s.dir.UpdateUser(name, func(u *User) error {
		u.Email, u.Disabled, u.Pending = addr, true, "verify"
		return nil
	})
	tok := s.acct.issue("verify", name, 24*time.Hour)
	link := s.publicBase(r) + "/#/verify/" + tok
	if err := s.sendMail(addr, "Confirm your "+s.Config().Name+" account", "Open this link within a day to confirm your email address:\n"+link); err != nil {
		s.dir.DeleteUser(name)
		s.log.Error("registration email failed", "err", err)
		apiError(w, http.StatusServiceUnavailable, errors.New("the confirmation email could not be sent; try again later"))
		return
	}
	s.log.Info("account registered, waiting for email confirmation", "user", name, "remote", ip)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Check your email for a link to confirm the account."})
}

func (s *Server) apiRegisterVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	user, ok := s.acct.redeem("verify", body.Token)
	if !ok {
		apiError(w, http.StatusBadRequest, errLinkExpired)
		return
	}
	approve := s.Config().Email.ApproveRegistrations
	s.dir.UpdateUser(user, func(u *User) error {
		if approve {
			u.Pending = "approval"
		} else {
			u.Pending, u.Disabled = "", false
		}
		return nil
	})
	if approve {
		for _, a := range s.dir.Users() {
			if a.Admin && a.Email != "" {
				go s.sendMail(a.Email, "New account waiting for approval", user+" registered on "+s.Config().Name+". Approve it in the dashboard under Users.")
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "Your email is confirmed. An administrator will approve the account."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Your account is ready. Sign in."})
}

func (s *Server) apiUserApprove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	u, ok := s.dir.User(name)
	if !ok || u.Pending == "" {
		apiError(w, http.StatusNotFound, errors.New("no account waiting for approval with that name"))
		return
	}
	s.dir.UpdateUser(name, func(u *User) error {
		u.Pending, u.Disabled = "", false
		return nil
	})
	if u.Email != "" {
		go s.sendMail(u.Email, "Your "+s.Config().Name+" account is approved", "You can now sign in as "+u.Name+".")
	}
	s.log.Info("account approved", "user", name, "by", identityOf(r).Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiEmailTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		To string `json:"to"`
	}
	if err := decodeBody(r, &body); err != nil || body.To == "" {
		apiError(w, http.StatusBadRequest, errors.New("enter an address to send the test to"))
		return
	}
	if err := s.sendMail(body.To, "GolangTAKServer test message", "Email from "+s.Config().Name+" works."); err != nil {
		apiError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
