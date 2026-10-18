package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/grpcx"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

const fedTokenAudience = "golangtakserver-federation"

type fedTokenClaims struct {
	Name          string `json:"name"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	CAFingerprint string `json:"caFingerprint,omitempty"`
	PrincipalDN   string `json:"principalDN,omitempty"`
	IssuerDN      string `json:"issuerDN,omitempty"`
	Aud           string `json:"aud"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp,omitempty"`
	Jti           string `json:"jti"`
}

func (s *Server) signFedToken(c fedTokenClaims) string {
	c.Aud = fedTokenAudience
	c.Iat = time.Now().Unix()
	if c.Jti == "" {
		c.Jti = NewSecret(12)
	}
	payload, _ := json.Marshal(c)
	body := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) parseFedToken(t string) (fedTokenClaims, error) {
	var c fedTokenClaims
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[0] != jwtHeader || len(s.tokenKey) == 0 {
		return c, errors.New("not a federation token from this server")
	}
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return c, errors.New("bad token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return c, errors.New("malformed token")
	}
	if c.Aud != fedTokenAudience || c.Name == "" {
		return c, errors.New("not a federation token")
	}
	if c.Exp > 0 && time.Now().Unix() >= c.Exp {
		return c, errors.New("token expired")
	}
	return c, nil
}

func (s *Server) fedTokenAllowed(c fedTokenClaims) error {
	cfg := s.Config().Federation
	if f, ok := cfg.federate(c.Fingerprint, c.Name); ok && f.TokenFederate && !f.Disabled {
		return nil
	}
	if ca, ok := cfg.federateCA(c.CAFingerprint); ok && ca.AllowTokenAuth {
		return nil
	}
	return errors.New("token is valid but not defined in the config")
}

func bearerOf(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) startFederationToken() error {
	cfg := s.Config()
	t := cfg.Federation.Token
	if !cfg.Federation.Enabled || !t.Enabled || s.fig2 == nil {
		return nil
	}
	port := t.Port
	if port <= 0 {
		port = 9002
	}
	ln, err := s.listenTCP(port)
	if err != nil {
		return err
	}
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven,
		NextProtos: []string{"h2"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.pki.ServerCert(), nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error { return s.revocationErr(cs.VerifiedChains) },
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		c.ClientCAs = s.federationTrust()
		return c, nil
	}
	hs := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.fig2.serve(w, r.WithContext(context.WithValue(r.Context(), keyListener, "fedtoken")))
		}),
		ReadHeaderTimeout: 20 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
	}
	s.lmu.Lock()
	s.https = append(s.https, hs)
	s.lmu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		hs.Serve(tls.NewListener(ln, base))
	}()
	s.log.Info("federation token port listening", "port", port)
	return nil
}

func (f *fig2Server) issueTokenByX509(st *grpcx.ServerStream, r *http.Request) {
	msg, err := st.Recv()
	if err != nil {
		st.Finish(grpcx.Errorf(grpcx.InvalidArgument, "send the federate certificate"))
		return
	}
	blob, err := takproto.UnmarshalBlob(msg)
	if err != nil || len(blob.Data) == 0 {
		st.Finish(grpcx.Errorf(grpcx.InvalidArgument, "send the federate certificate"))
		return
	}
	cert, err := x509.ParseCertificate(blob.Data)
	if err != nil {
		st.Finish(grpcx.Errorf(grpcx.InvalidArgument, "the certificate could not be read"))
		return
	}
	cfg := f.s.Config().Federation
	if !cfg.Token.AllowWithoutTLSCert {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !r.TLS.PeerCertificates[0].Equal(cert) {
			st.Finish(grpcx.Errorf(grpcx.Unauthenticated, "present the same certificate on the TLS connection"))
			return
		}
	}
	chains, err := cert.Verify(x509.VerifyOptions{Roots: f.s.federationTrust(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		st.Finish(grpcx.Errorf(grpcx.Unauthenticated, "the certificate is not signed by a trusted federation CA"))
		return
	}
	caFP := chainCAFingerprint(chains)
	if caFP == "" && len(chains) > 0 && len(chains[0]) > 0 {
		caFP = certFingerprint(chains[0][len(chains[0])-1])
	}
	ca, ok := cfg.federateCA(caFP)
	if !ok || !ca.AllowTokenAuth {
		st.Finish(grpcx.Errorf(grpcx.PermissionDenied, "token authentication is not enabled for this certificate authority"))
		return
	}
	claims := fedTokenClaims{Name: cert.Subject.CommonName + " (" + cert.Issuer.CommonName + ")", Fingerprint: certFingerprint(cert), CAFingerprint: caFP,
		PrincipalDN: cert.Subject.String(), IssuerDN: cert.Issuer.String()}
	if ca.TokenAuthDays > 0 {
		claims.Exp = time.Now().Add(time.Duration(ca.TokenAuthDays) * 24 * time.Hour).Unix()
	}
	f.s.log.Info("federation token issued", "federate", claims.Name)
	st.Finish(st.Send(takproto.MarshalToken(f.s.signFedToken(claims))))
}

func (f *fig2Server) tokenSession(r *http.Request) (*fig2Session, error) {
	tok := bearerOf(r)
	if tok == "" {
		return nil, grpcx.Errorf(grpcx.Unauthenticated, "Authorization token is missing")
	}
	claims, err := f.s.parseFedToken(tok)
	if err != nil {
		return nil, grpcx.Errorf(grpcx.Unauthenticated, "%v", err)
	}
	if err := f.s.fedTokenAllowed(claims); err != nil {
		return nil, grpcx.Errorf(grpcx.PermissionDenied, "%v", err)
	}
	key := "token:" + firstNonEmpty(claims.Fingerprint, claims.Jti)
	f.mu.Lock()
	defer f.mu.Unlock()
	if ss, ok := f.sessions[key]; ok {
		ss.refs++
		return ss, nil
	}
	pol := f.s.fedPolicyFor(claims.Fingerprint, claims.Name, claims.CAFingerprint, nil)
	if pol.disabled {
		return nil, grpcx.Errorf(grpcx.PermissionDenied, "this federate is disabled")
	}
	c := f.s.fedClient(KindFederation, claims.Name, r.RemoteAddr, pol)
	f.s.hub.Add(c)
	f.s.noteFederate(pol, r.RemoteAddr, "v2", "inbound", nil, true)
	ss := &fig2Session{key: key, name: claims.Name, remote: r.RemoteAddr, c: c, allowed: pol.out, refs: 1, since: time.Now(), rolOut: make(chan takproto.ROL, 256), done: make(chan struct{})}
	f.sessions[key] = ss
	f.s.fed.add(&fedConn{c: c, name: claims.Name, dir: "inbound", since: ss.since, version: "v2 token"})
	f.s.log.Info("federate connected", "federate", claims.Name, "direction", "inbound", "version", "v2", "auth", "token", "remote", r.RemoteAddr)
	return ss, nil
}

type jwtTokenRequest struct {
	Expiration int64          `json:"expiration"`
	Attributes map[string]any `json:"attributes"`
}

func (s *Server) fedTokenFromRequest(r *http.Request) (string, fedTokenClaims, error) {
	var req jwtTokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		return "", fedTokenClaims{}, errors.New("expected a token request")
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := req.Attributes[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	c := fedTokenClaims{Name: str("name", "clientName", "federateName", "federate"), Fingerprint: normFingerprint(str("fingerprint", "clientFingerprint"))}
	if c.Name == "" {
		c.Name = "token-federate-" + cot.NewUID()[:8]
	}
	if req.Expiration > 0 {
		exp := req.Expiration
		if exp > 1e12 {
			exp /= 1000
		}
		if exp < 1e9 {
			exp = time.Now().Unix() + exp
		}
		c.Exp = exp
	}
	return s.signFedToken(c), c, nil
}

func (s *Server) martiGenerateFedToken(w http.ResponseWriter, r *http.Request) {
	tok, _, err := s.fedTokenFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", tok))
}

func (s *Server) martiGenerateAndSaveFedToken(w http.ResponseWriter, r *http.Request) {
	tok, c, err := s.fedTokenFromRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, s.envelope("error", err.Error()))
		return
	}
	_, err = s.UpdateConfig(func(cfg *Config) error {
		id := firstNonEmpty(c.Fingerprint, c.Name)
		for i := range cfg.Federation.Federates {
			if cfg.Federation.Federates[i].ID == id || strings.EqualFold(cfg.Federation.Federates[i].Name, c.Name) {
				cfg.Federation.Federates[i].TokenFederate = true
				cfg.Federation.Federates[i].TokenExpiration = c.Exp
				return nil
			}
		}
		cfg.Federation.Federates = append(cfg.Federation.Federates, FederateConfig{ID: id, Name: c.Name, TokenFederate: true, TokenExpiration: c.Exp})
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, s.envelope("error", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("java.lang.String", tok))
}
