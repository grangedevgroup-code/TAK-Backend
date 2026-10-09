package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type missionClaims struct {
	JTI     string `json:"jti"`
	IAT     int64  `json:"iat"`
	Sub     string `json:"sub"`
	Iss     string `json:"iss"`
	Mission string `json:"MISSION_NAME"`
	GUID    string `json:"MISSION_GUID"`
}

var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

func loadTokenKey(dataDir string) ([]byte, error) {
	p := filepath.Join(certDir(dataDir), "mission-token.key")
	b, err := os.ReadFile(p)
	if err == nil && len(b) >= 32 {
		return b[:32], nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(p, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Server) signMissionToken(c missionClaims) string {
	if c.JTI == "" {
		c.JTI = NewSecret(12)
	}
	if c.IAT == 0 {
		c.IAT = time.Now().Unix()
	}
	c.Iss = "GolangTAKServer"
	payload, _ := json.Marshal(c)
	body := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) parseMissionToken(t string) (missionClaims, error) {
	var c missionClaims
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[0] != jwtHeader || len(s.tokenKey) == 0 {
		return c, errors.New("not a mission token")
	}
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return c, errors.New("bad mission token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, err
	}
	return c, nil
}

func (s *Server) isMissionToken(t string) bool {
	c, err := s.parseMissionToken(t)
	return err == nil && (c.Mission != "" || c.GUID != "")
}
