package server

import (
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/ldap"
)

var errLDAPOff = errors.New("LDAP sign-in is not enabled")

func (s *Server) ldapConfig(c LDAPConfig) (ldap.Config, error) {
	lc := ldap.Config{
		URL: c.URL, StartTLS: c.StartTLS, Insecure: c.Insecure, BindDN: c.BindDN, BindPassword: c.BindPassword,
		BaseDN: c.BaseDN, UserFilter: c.UserFilter, UserDN: c.UserDN, GroupFilter: c.GroupFilter, GroupBaseDN: c.GroupBaseDN,
		Timeout: 10 * time.Second,
	}
	if c.CallsignAttribute != "" {
		lc.Attributes = []string{c.CallsignAttribute}
	}
	if c.TrustFile != "" {
		pem, err := os.ReadFile(c.TrustFile)
		if err != nil {
			return lc, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return lc, errors.New("no certificates in " + c.TrustFile)
		}
		lc.RootCAs = pool
	}
	return lc, nil
}

func (s *Server) ldapLookup(c LDAPConfig, name, password string) (*ExternalAuth, error) {
	lc, err := s.ldapConfig(c)
	if err != nil {
		return nil, err
	}
	e, err := ldap.Authenticate(lc, name, password)
	if err != nil {
		return nil, err
	}
	return mapLDAPEntry(c, e), nil
}

func mapLDAPEntry(c LDAPConfig, e *ldap.Entry) *ExternalAuth {
	res := &ExternalAuth{}
	seen := map[string]bool{}
	for _, g := range e.Groups {
		cn := ldap.CommonName(g)
		if c.AdminGroup != "" && strings.EqualFold(cn, c.AdminGroup) {
			res.Admin = true
		}
		if c.GroupPrefix != "" {
			if len(cn) <= len(c.GroupPrefix) || !strings.EqualFold(cn[:len(c.GroupPrefix)], c.GroupPrefix) {
				continue
			}
			cn = cn[len(c.GroupPrefix):]
		}
		if validGroup.MatchString(cn) && !seen[cn] {
			seen[cn] = true
			res.Groups = append(res.Groups, cn)
		}
	}
	if c.CallsignAttribute != "" {
		res.Callsign = strings.TrimSpace(e.First(c.CallsignAttribute))
	}
	return res
}

func (s *Server) ldapAuth(name, password string) (*ExternalAuth, error) {
	c := s.Config().LDAP
	if !c.Enabled {
		return nil, errLDAPOff
	}
	res, err := s.ldapLookup(c, name, password)
	if err != nil {
		if !errors.Is(err, ldap.ErrInvalidCredentials) && !errors.Is(err, ldap.ErrUserNotFound) {
			s.log.Warn("LDAP sign-in failed", "user", name, "err", err)
		}
		return nil, err
	}
	s.log.Info("LDAP sign-in", "user", name, "groups", strings.Join(res.Groups, ","), "admin", res.Admin)
	return res, nil
}

func (s *Server) apiLDAPTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string      `json:"username"`
		Password string      `json:"password"`
		Config   *LDAPConfig `json:"config"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	c := s.Config().LDAP
	if body.Config != nil {
		saved := c.BindPassword
		c = *body.Config
		if c.BindPassword == "********" {
			c.BindPassword = saved
		}
	}
	res, err := s.ldapLookup(c, body.Username, body.Password)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "groups": res.Groups, "admin": res.Admin, "callsign": res.Callsign})
}
