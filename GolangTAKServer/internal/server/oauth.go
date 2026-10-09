package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	oauthAudience = "golangtakserver"
	oauthTTL      = 8 * time.Hour
)

type oauthClaims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
}

func (s *Server) signOAuthToken(user string, ttl time.Duration) (string, oauthClaims) {
	now := time.Now()
	c := oauthClaims{Sub: user, Aud: oauthAudience, Nbf: now.Unix() - 5, Exp: now.Add(ttl).Unix(), Iat: now.Unix(), Jti: NewSecret(12)}
	payload, _ := json.Marshal(c)
	for len(payload)%3 != 0 {
		payload = append(payload[:len(payload)-1], ' ', '}')
	}
	body := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), c
}

func (s *Server) parseOAuthToken(t string) (oauthClaims, error) {
	var c oauthClaims
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[0] != jwtHeader || len(s.tokenKey) == 0 {
		return c, errors.New("not an oauth token")
	}
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return c, errors.New("bad token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, err
	}
	now := time.Now().Unix()
	if (c.Aud != oauthAudience && c.Aud != legacyOAuthAudience) || c.Sub == "" || now >= c.Exp || now < c.Nbf {
		return c, errors.New("token expired or not valid here")
	}
	return c, nil
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "could not read the request"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	switch grant := r.Form.Get("grant_type"); grant {
	case "password":
	case "refresh_token":
		c, err := s.parseOAuthToken(r.Form.Get("refresh_token"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Invalid refresh token"})
			return
		}
		if _, err := s.dir.Identity(c.Sub, "oauth"); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Bad credentials"})
			return
		}
		s.writeOAuth(w, c.Sub)
		return
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type", "error_description": "Unsupported grant type: " + grant})
		return
	}
	id, err := s.dir.CheckPassword(requestIP(r), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrThrottled) {
			status = http.StatusTooManyRequests
		}
		s.log.Warn("oauth sign-in failed", "user", r.Form.Get("username"), "remote", requestIP(r))
		writeJSON(w, status, map[string]string{"error": "invalid_grant", "error_description": "Bad credentials"})
		return
	}
	s.log.Info("oauth sign-in", "user", id.Name, "remote", requestIP(r))
	s.writeOAuth(w, id.Name)
}

func (s *Server) writeOAuth(w http.ResponseWriter, user string) {
	tok, c := s.signOAuthToken(user, oauthTTL)
	refresh, _ := s.signOAuthToken(user, 7*24*time.Hour)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "bearer", "refresh_token": refresh, "expires_in": int(oauthTTL / time.Second), "scope": "read write", "jti": c.Jti})
}
