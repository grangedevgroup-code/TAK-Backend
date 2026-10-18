package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

func (s *Server) martiSecurityConfigPut(w http.ResponseWriter, r *http.Request) {
	var b struct {
		X509AddAnonymous *bool   `json:"x509addAnonymous"`
		X509AddAnon      *bool   `json:"x509addAnon"`
		ValidityDays     *int    `json:"validityDays"`
		CAType           *string `json:"caType"`
		MSCAUserName     *string `json:"mscaUserName"`
		MSCAPassword     *string `json:"mscaPassword"`
		MSCATemplateName *string `json:"mscaTemplateName"`
		MSCAURL          *string `json:"mscaUrl"`
		EnableEnrollment *bool   `json:"enableEnrollment"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected a security configuration"))
		return
	}
	restart := false
	_, err := s.UpdateConfig(func(c *Config) error {
		if v := b.X509AddAnonymous; v != nil {
			c.AllowAnonymous = *v
		} else if v := b.X509AddAnon; v != nil {
			c.AllowAnonymous = *v
		}
		if b.ValidityDays != nil {
			if *b.ValidityDays < 1 || *b.ValidityDays > 3650 {
				return errors.New("validityDays must be between 1 and 3650")
			}
			c.Certificates.ClientDays = *b.ValidityDays
		}
		if b.CAType != nil {
			if strings.EqualFold(*b.CAType, "MicrosoftCA") {
				c.Certificates.External.Mode = "certsrv"
			} else {
				c.Certificates.External.Mode = ""
			}
		}
		if b.MSCAUserName != nil {
			c.Certificates.External.Username = *b.MSCAUserName
		}
		if b.MSCAPassword != nil && *b.MSCAPassword != "********" {
			c.Certificates.External.Password = *b.MSCAPassword
		}
		if b.MSCATemplateName != nil {
			c.Certificates.External.Template = *b.MSCATemplateName
		}
		if b.MSCAURL != nil {
			c.Certificates.External.URL = *b.MSCAURL
		}
		if b.EnableEnrollment != nil {
			if *b.EnableEnrollment && c.Ports.Enroll == 0 {
				c.Ports.Enroll, restart = DefaultConfig().Ports.Enroll, true
			} else if !*b.EnableEnrollment && c.Ports.Enroll != 0 {
				c.Ports.Enroll, restart = 0, true
			}
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.SecurityConfigInfo", map[string]any{"restartRequired": restart}))
}

func (s *Server) ldapConfigJSON(ld LDAPConfig) map[string]any {
	return map[string]any{"url": ld.URL, "userstring": ld.UserDN, "updateinterval": 60, "style": firstNonEmpty(ld.Style, "DS"), "ldapSecurityType": "simple",
		"serviceAccountDN": ld.BindDN, "serviceAccountCredential": map[bool]string{true: "********", false: ""}[ld.BindPassword != ""], "groupBaseRDN": ld.GroupBaseDN,
		"groupprefix": ld.GroupPrefix, "groupNameExtractorRegex": ld.GroupNameRegex, "callsignAttribute": ld.CallsignAttribute, "colorAttribute": ld.ColorAttribute,
		"roleAttribute": ld.RoleAttribute, "adminGroup": ld.AdminGroup, "readOnlyGroup": ld.ReadOnlyGroup, "readGroupSuffix": ld.ReadGroupSuffix,
		"writeGroupSuffix": ld.WriteGroupSuffix, "ldapsTruststoreFile": ld.TrustFile, "loginWithEmail": ld.LoginWithEmail, "nestedGroupLookup": ld.NestedGroups,
		"nestedGroupMaxSearchDepth": ld.NestedMaxDepth, "enabled": ld.Enabled, "userFilter": ld.UserFilter, "groupFilter": ld.GroupFilter, "baseDn": ld.BaseDN}
}

func (s *Server) martiAuthConfigPut(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL               *string `json:"url"`
		UserString        *string `json:"userstring"`
		Style             *string `json:"style"`
		ServiceAccountDN  *string `json:"serviceAccountDN"`
		ServiceAccountPW  *string `json:"serviceAccountCredential"`
		GroupBaseRDN      *string `json:"groupBaseRDN"`
		UserBaseRDN       *string `json:"userBaseRDN"`
		GroupPrefix       *string `json:"groupprefix"`
		GroupNameRegex    *string `json:"groupNameExtractorRegex"`
		CallsignAttribute *string `json:"callsignAttribute"`
		ColorAttribute    *string `json:"colorAttribute"`
		RoleAttribute     *string `json:"roleAttribute"`
		AdminGroup        *string `json:"adminGroup"`
		ReadOnlyGroup     *string `json:"readOnlyGroup"`
		ReadGroupSuffix   *string `json:"readGroupSuffix"`
		WriteGroupSuffix  *string `json:"writeGroupSuffix"`
		TrustFile         *string `json:"ldapsTruststoreFile"`
		LoginWithEmail    *bool   `json:"loginWithEmail"`
		NestedGroupLookup *bool   `json:"nestedGroupLookup"`
		NestedDepth       *int    `json:"nestedGroupMaxSearchDepth"`
		Enabled           *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&b); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "expected an authentication configuration"))
		return
	}
	if b.GroupNameRegex != nil && *b.GroupNameRegex != "" {
		if _, err := regexp.Compile(*b.GroupNameRegex); err != nil {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "groupNameExtractorRegex: "+err.Error()))
			return
		}
	}
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
		}
	}
	cfg, err := s.UpdateConfig(func(c *Config) error {
		ld := &c.LDAP
		set(&ld.URL, b.URL)
		if b.UserString != nil {
			ld.UserDN = strings.ReplaceAll(*b.UserString, "{username}", "{user}")
		}
		set(&ld.Style, b.Style)
		set(&ld.BindDN, b.ServiceAccountDN)
		if b.ServiceAccountPW != nil && *b.ServiceAccountPW != "********" {
			ld.BindPassword = *b.ServiceAccountPW
		}
		set(&ld.GroupBaseDN, b.GroupBaseRDN)
		if b.UserBaseRDN != nil && ld.BaseDN == "" {
			ld.BaseDN = *b.UserBaseRDN
		}
		set(&ld.GroupPrefix, b.GroupPrefix)
		set(&ld.GroupNameRegex, b.GroupNameRegex)
		set(&ld.CallsignAttribute, b.CallsignAttribute)
		set(&ld.ColorAttribute, b.ColorAttribute)
		set(&ld.RoleAttribute, b.RoleAttribute)
		set(&ld.AdminGroup, b.AdminGroup)
		set(&ld.ReadOnlyGroup, b.ReadOnlyGroup)
		set(&ld.ReadGroupSuffix, b.ReadGroupSuffix)
		set(&ld.WriteGroupSuffix, b.WriteGroupSuffix)
		set(&ld.TrustFile, b.TrustFile)
		if b.LoginWithEmail != nil {
			ld.LoginWithEmail = *b.LoginWithEmail
		}
		if b.NestedGroupLookup != nil {
			ld.NestedGroups = *b.NestedGroupLookup
		}
		if b.NestedDepth != nil {
			ld.NestedMaxDepth = *b.NestedDepth
		}
		if b.Enabled != nil {
			ld.Enabled = *b.Enabled
		} else if b.URL != nil {
			ld.Enabled = ld.URL != ""
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.remote.AuthenticationConfigInfo", s.ldapConfigJSON(cfg.LDAP)))
}

func (s *Server) martiAuthConfigTest(w http.ResponseWriter, r *http.Request) {
	ld := s.Config().LDAP
	if !ld.Enabled || ld.URL == "" {
		writeJSON(w, http.StatusBadRequest, s.envelope("java.lang.String", "LDAP is not configured"))
		return
	}
	if err := s.ldapCheckService(ld); err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("java.lang.String", "LDAP test failed: "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", "LDAP connection and service account bind succeeded"))
}

const inviteKind = "invite"

type inviteData struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

func (s *Server) registerInvite(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	addr := strings.TrimSpace(q.Get("emailAddress"))
	if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "enter a valid email address"))
		return
	}
	groups := q["group"]
	if len(groups) == 0 {
		groups = []string{s.dir.AnonGroup()}
	}
	for _, g := range groups {
		if !validGroup.MatchString(g) {
			writeJSON(w, http.StatusBadRequest, s.envelope("error", "invalid group name "+g))
			return
		}
	}
	data, _ := json.Marshal(inviteData{Email: addr, Groups: groups})
	tok := s.acct.issue(inviteKind, string(data), 7*24*time.Hour)
	link := s.publicBase(r) + "/register/token/" + tok
	body := fmt.Sprintf("You are invited to %s.\n\nOpen this link within 7 days to create your account:\n%s\n", s.Config().Name, link)
	if err := s.sendMail(addr, "Your "+s.Config().Name+" account", body); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, s.envelope("error", "the invitation email could not be sent: "+err.Error()))
		return
	}
	s.log.Info("registration invitation sent", "email", addr, "groups", strings.Join(groups, ","), "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", "invitation sent"))
}

func (s *Server) registerSignUp(w http.ResponseWriter, r *http.Request) {
	ec := s.Config().Email
	q := r.URL.Query()
	addr := strings.TrimSpace(q.Get("emailAddress"))
	if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", "enter a valid email address"))
		return
	}
	groups, listed := registrationGroups(ec, addr, strings.TrimSpace(q.Get("token")))
	if !ec.Enabled || !ec.AllowRegistration || !domainAllowed(ec, addr) || !listed {
		writeJSON(w, http.StatusForbidden, s.envelope("error", "registration is not open for that email address"))
		return
	}
	ip := requestIP(r)
	if authLimiter.blocked(ip) {
		writeJSON(w, http.StatusTooManyRequests, s.envelope("error", ErrThrottled.Error()))
		return
	}
	authLimiter.fail(ip)
	for _, g := range groups {
		s.dir.EnsureGroup(g, "Registration", false)
	}
	data, _ := json.Marshal(inviteData{Email: addr, Groups: groups})
	tok := s.acct.issue(inviteKind, string(data), 24*time.Hour)
	link := s.publicBase(r) + "/register/token/" + tok
	if err := s.sendMail(addr, "Confirm your "+s.Config().Name+" account", "Open this link within a day to create your account:\n"+link); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, s.envelope("error", "the confirmation email could not be sent"))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", "Check your email for a link to create the account."))
}

func userNameFromEmail(addr string) string {
	local := strings.ToLower(addr)
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '@' {
			return r
		}
		return -1
	}, local)
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}

func (s *Server) registerConfirm(w http.ResponseWriter, r *http.Request) {
	raw, ok := s.acct.redeem(inviteKind, r.PathValue("token"))
	page := func(status int, title, msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>%s</title><body style="font-family:sans-serif;max-width:36em;margin:3em auto;padding:0 1em"><h1>%s</h1><p>%s</p><p><a href="/">Open %s</a></p>`,
			htmlEscape(title), htmlEscape(title), msg, htmlEscape(s.Config().Name))
	}
	if !ok {
		page(http.StatusBadRequest, "Link expired", "This link was already used or has expired. Ask an administrator for a new invitation.")
		return
	}
	var inv inviteData
	if json.Unmarshal([]byte(raw), &inv) != nil || inv.Email == "" {
		page(http.StatusBadRequest, "Invalid link", "This invitation could not be read.")
		return
	}
	for _, u := range s.dir.Users() {
		if strings.EqualFold(u.Email, inv.Email) {
			page(http.StatusConflict, "Account exists", "An account already uses this email address. Sign in or reset your password.")
			return
		}
	}
	name := userNameFromEmail(inv.Email)
	password := FriendlySecret()
	if _, err := s.dir.AddUser(name, password, false, inv.Groups); err != nil {
		page(http.StatusBadRequest, "Account not created", htmlEscape(err.Error()))
		return
	}
	s.dir.UpdateUser(name, func(u *User) error {
		u.Email = inv.Email
		if s.Config().Email.ApproveRegistrations {
			u.Pending, u.Disabled = "approval", true
		}
		return nil
	})
	go s.sendMail(inv.Email, "Your "+s.Config().Name+" account", "User name: "+name+"\nPassword: "+password+"\n\nChange the password after you sign in.")
	s.log.Info("account created from invitation", "user", name)
	page(http.StatusOK, "Account created", "User name: <b>"+htmlEscape(name)+"</b><br>Password: <b>"+htmlEscape(password)+"</b><br><br>The details were also emailed to you. Change the password after you sign in.")
}

func (s *Server) registerUsers(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, u := range s.dir.Users() {
		if u.Email == "" {
			continue
		}
		out = append(out, map[string]any{"username": u.Name, "emailAddress": u.Email, "pending": u.Pending, "disabled": u.Disabled, "groups": u.In, "created": isoTime(u.Created)})
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.user.registration.model.User", out))
}

func (s *Server) filesConfigSet(w http.ResponseWriter, r *http.Request) {
	var b struct {
		UploadSizeLimit int `json:"uploadSizeLimit"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b); err != nil || b.UploadSizeLimit <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "uploadSizeLimit must be a positive number of megabytes"})
		return
	}
	cfg, err := s.UpdateConfig(func(c *Config) error { c.Limits.MaxUploadMB = b.UploadSizeLimit; return nil })
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uploadSizeLimit": cfg.Limits.MaxUploadMB})
}

func (s *Server) secConfigRoutes(m, a, pub func(string, http.HandlerFunc)) {
	a("PUT /Marti/api/security/config", s.martiSecurityConfigPut)
	a("PUT /Marti/api/authentication/config", s.martiAuthConfigPut)
	a("POST /Marti/api/authentication/config", s.martiAuthConfigTest)
	a("POST /register/admin/invite", s.registerInvite)
	a("GET /register/admin/users", s.registerUsers)
	pub("POST /register/user", s.registerSignUp)
	pub("GET /register/token/{token}", s.registerConfirm)
	a("POST /files/api/config", s.filesConfigSet)
	m("GET /Marti/files/api/config", s.filesConfig)
	a("POST /Marti/files/api/config", s.filesConfigSet)
	m("GET /vbm/api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, s.Config().VBM) })
	a("POST /vbm/api/config", s.vbmSet)
	m("GET /vbm/api/classification", func(w http.ResponseWriter, r *http.Request) {
		writeText(w, http.StatusOK, s.Config().VBM.NetworkClassification)
	})
}
