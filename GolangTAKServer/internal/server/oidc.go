package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type OAuthConfig struct {
	Enabled         bool     `json:"enabled"`
	Name            string   `json:"name,omitempty"`
	Issuer          string   `json:"issuer,omitempty"`
	DiscoveryURL    string   `json:"discoveryUrl,omitempty"`
	AuthEndpoint    string   `json:"authEndpoint,omitempty"`
	TokenEndpoint   string   `json:"tokenEndpoint,omitempty"`
	JWKSURL         string   `json:"jwksUrl,omitempty"`
	ClientID        string   `json:"clientId,omitempty"`
	ClientSecret    string   `json:"clientSecret,omitempty"`
	RedirectURI     string   `json:"redirectUri,omitempty"`
	Scope           string   `json:"scope,omitempty"`
	Audience        string   `json:"audience,omitempty"`
	UsernameClaim   string   `json:"usernameClaim,omitempty"`
	GroupsClaim     string   `json:"groupsClaim,omitempty"`
	CallsignClaim   string   `json:"callsignClaim,omitempty"`
	GroupPrefix     string   `json:"groupPrefix,omitempty"`
	GroupNameRegex  string   `json:"groupNameRegex,omitempty"`
	AdminGroup      string   `json:"adminGroup,omitempty"`
	AdminClaimName  string   `json:"adminClaimName,omitempty"`
	AdminClaimValue string   `json:"adminClaimValue,omitempty"`
	AddAnonymous    bool     `json:"addAnonymous,omitempty"`
	PublicKeys      []string `json:"publicKeys,omitempty"`
	TrustFile       string   `json:"trustFile,omitempty"`
	Insecure        bool     `json:"insecure,omitempty"`
	LoginButton     bool     `json:"loginButton,omitempty"`
}

func (c OAuthConfig) usable() bool {
	return c.Enabled && (c.Issuer != "" || c.DiscoveryURL != "" || c.JWKSURL != "" || len(c.PublicKeys) > 0)
}

type oidcDiscovery struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	JWKS          string `json:"jwks_uri"`
	EndSession    string `json:"end_session_endpoint"`
	raw           []byte
}

type oidcCached struct {
	id      *Identity
	expires time.Time
}

type oidcState struct {
	mu        sync.Mutex
	cfgKey    string
	disc      *oidcDiscovery
	discAt    time.Time
	keys      map[string]crypto.PublicKey
	anonKeys  []crypto.PublicKey
	keysAt    time.Time
	idCache   map[string]oidcCached
	client    *http.Client
	issued    *store.Collection[issuedToken]
	revoked   *store.Collection[issuedToken]
	revokedMu sync.RWMutex
	revSet    map[string]bool
}

type issuedToken struct {
	JTI      string    `json:"jti"`
	User     string    `json:"user"`
	ClientID string    `json:"clientId"`
	Refresh  bool      `json:"refresh,omitempty"`
	Issued   time.Time `json:"issued"`
	Expires  time.Time `json:"expires"`
}

func openOIDC(dataDir string) (*oidcState, error) {
	issued, err := store.Open[issuedToken](filepath.Join(dataDir, "db", "oauth-tokens.jsonl"), true)
	if err != nil {
		return nil, err
	}
	revoked, err := store.Open[issuedToken](filepath.Join(dataDir, "db", "oauth-revoked.jsonl"), true)
	if err != nil {
		issued.Close()
		return nil, err
	}
	o := &oidcState{idCache: map[string]oidcCached{}, issued: issued, revoked: revoked, revSet: map[string]bool{}}
	now := time.Now()
	for _, t := range revoked.All() {
		if t.Expires.After(now) {
			o.revSet[t.JTI] = true
		} else {
			revoked.Delete(t.JTI)
		}
	}
	return o, nil
}

func (o *oidcState) Close() {
	o.issued.Close()
	o.revoked.Close()
}

func (o *oidcState) record(c oauthClaims, clientID string, refresh bool) {
	if o == nil || c.Jti == "" {
		return
	}
	o.issued.Put(c.Jti, issuedToken{JTI: c.Jti, User: c.Sub, ClientID: clientID, Refresh: refresh, Issued: time.Unix(c.Iat, 0).UTC(), Expires: time.Unix(c.Exp, 0).UTC()})
	if o.issued.Len() > 20000 {
		o.prune()
	}
}

func (o *oidcState) prune() {
	now := time.Now()
	for _, t := range o.issued.All() {
		if t.Expires.Before(now) {
			o.issued.Delete(t.JTI)
		}
	}
	for _, t := range o.revoked.All() {
		if t.Expires.Before(now) {
			o.revoked.Delete(t.JTI)
			o.revokedMu.Lock()
			delete(o.revSet, t.JTI)
			o.revokedMu.Unlock()
		}
	}
}

func (o *oidcState) isRevoked(jti string) bool {
	if o == nil || jti == "" {
		return false
	}
	o.revokedMu.RLock()
	defer o.revokedMu.RUnlock()
	return o.revSet[jti]
}

func (o *oidcState) revoke(jti string) bool {
	t, ok := o.issued.Get(jti)
	if !ok {
		return false
	}
	o.revoked.Put(jti, t)
	o.issued.Delete(jti)
	o.revokedMu.Lock()
	o.revSet[jti] = true
	o.revokedMu.Unlock()
	return true
}

func (s *Server) oidcHTTPClient(c OAuthConfig) *http.Client {
	key := c.TrustFile + "|" + fmt.Sprint(c.Insecure)
	s.oidc.mu.Lock()
	defer s.oidc.mu.Unlock()
	if s.oidc.client != nil && s.oidc.cfgKey == key {
		return s.oidc.client
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.Insecure} // #nosec G402 -- administrator option for test identity providers
	if c.TrustFile != "" {
		if pemData, err := os.ReadFile(c.TrustFile); err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(pemData)
			tcfg.RootCAs = pool
		}
	}
	s.oidc.client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tcfg, Proxy: http.ProxyFromEnvironment}}
	s.oidc.cfgKey = key
	s.oidc.disc, s.oidc.keys, s.oidc.anonKeys = nil, nil, nil
	return s.oidc.client
}

func (s *Server) oidcDiscover(c OAuthConfig) (*oidcDiscovery, error) {
	client := s.oidcHTTPClient(c)
	s.oidc.mu.Lock()
	if d := s.oidc.disc; d != nil && time.Since(s.oidc.discAt) < time.Hour {
		s.oidc.mu.Unlock()
		return d, nil
	}
	s.oidc.mu.Unlock()
	d := &oidcDiscovery{Issuer: c.Issuer, Authorization: c.AuthEndpoint, Token: c.TokenEndpoint, JWKS: c.JWKSURL}
	u := c.DiscoveryURL
	if u == "" && c.Issuer != "" {
		u = strings.TrimRight(c.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if u != "" {
		resp, err := client.Get(u)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("identity provider discovery returned %s", resp.Status)
		}
		var got oidcDiscovery
		if err := json.Unmarshal(body, &got); err != nil {
			return nil, err
		}
		d.raw = body
		d.Issuer = firstNonEmpty(c.Issuer, got.Issuer)
		d.Authorization = firstNonEmpty(c.AuthEndpoint, got.Authorization)
		d.Token = firstNonEmpty(c.TokenEndpoint, got.Token)
		d.JWKS = firstNonEmpty(c.JWKSURL, got.JWKS)
		d.EndSession = got.EndSession
	}
	s.oidc.mu.Lock()
	s.oidc.disc, s.oidc.discAt = d, time.Now()
	s.oidc.mu.Unlock()
	return d, nil
}

func b64n(v string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func parseJWK(k map[string]any) (crypto.PublicKey, error) {
	str := func(n string) string { v, _ := k[n].(string); return v }
	switch str("kty") {
	case "RSA":
		n, err := b64n(str("n"))
		if err != nil {
			return nil, err
		}
		e, err := b64n(str("e"))
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch str("crv") {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported curve")
		}
		x, err := b64n(str("x"))
		if err != nil {
			return nil, err
		}
		y, err := b64n(str("y"))
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		b, err := base64.RawURLEncoding.DecodeString(str("x"))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(b), nil
	}
	return nil, errors.New("unsupported key type")
}

func parsePEMPublicKeys(list []string) []crypto.PublicKey {
	var out []crypto.PublicKey
	for _, item := range list {
		data := []byte(item)
		if !strings.Contains(item, "-----BEGIN") {
			if b, err := os.ReadFile(item); err == nil {
				data = b
			}
		}
		for {
			var blk *pem.Block
			blk, data = pem.Decode(data)
			if blk == nil {
				break
			}
			switch blk.Type {
			case "CERTIFICATE":
				if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
					out = append(out, c.PublicKey)
				}
			case "PUBLIC KEY":
				if k, err := x509.ParsePKIXPublicKey(blk.Bytes); err == nil {
					out = append(out, k)
				}
			case "RSA PUBLIC KEY":
				if k, err := x509.ParsePKCS1PublicKey(blk.Bytes); err == nil {
					out = append(out, k)
				}
			}
		}
	}
	return out
}

func (s *Server) oidcKeys(c OAuthConfig, kid string, force bool) (map[string]crypto.PublicKey, []crypto.PublicKey, error) {
	s.oidc.mu.Lock()
	keys, anon, at := s.oidc.keys, s.oidc.anonKeys, s.oidc.keysAt
	s.oidc.mu.Unlock()
	_, known := keys[kid]
	if keys != nil && time.Since(at) < 10*time.Minute && (known || !force) {
		return keys, anon, nil
	}
	if keys != nil && force && time.Since(at) < 30*time.Second {
		return keys, anon, nil
	}
	keys = map[string]crypto.PublicKey{}
	anon = parsePEMPublicKeys(c.PublicKeys)
	d, err := s.oidcDiscover(c)
	if err == nil && d.JWKS != "" {
		resp, err := s.oidcHTTPClient(c).Get(d.JWKS)
		if err != nil {
			return nil, nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(body, &set); err != nil {
			return nil, nil, err
		}
		for _, k := range set.Keys {
			if use, _ := k["use"].(string); use != "" && use != "sig" {
				continue
			}
			pk, err := parseJWK(k)
			if err != nil {
				continue
			}
			if id, _ := k["kid"].(string); id != "" {
				keys[id] = pk
			} else {
				anon = append(anon, pk)
			}
		}
	} else if err != nil && len(anon) == 0 {
		return nil, nil, err
	}
	s.oidc.mu.Lock()
	s.oidc.keys, s.oidc.anonKeys, s.oidc.keysAt = keys, anon, time.Now()
	s.oidc.mu.Unlock()
	return keys, anon, nil
}

func verifyJWTSignature(alg string, key crypto.PublicKey, signed, sig []byte) bool {
	if len(alg) != 5 {
		return false
	}
	var h crypto.Hash
	switch alg[2:] {
	case "256":
		h = crypto.SHA256
	case "384":
		h = crypto.SHA384
	case "512":
		h = crypto.SHA512
	}
	if alg == "EdDSA" {
		k, ok := key.(ed25519.PublicKey)
		return ok && ed25519.Verify(k, signed, sig)
	}
	if h == 0 {
		return false
	}
	hh := h.New()
	hh.Write(signed)
	digest := hh.Sum(nil)
	switch alg[:2] {
	case "RS":
		k, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(k, h, digest, sig) == nil
	case "PS":
		k, ok := key.(*rsa.PublicKey)
		return ok && rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case "ES":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig)%2 != 0 {
			return false
		}
		n := len(sig) / 2
		return ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
	}
	return false
}

func looksLikeJWT(t string) bool {
	return strings.Count(t, ".") == 2 && len(t) > 20 && strings.HasPrefix(t, "eyJ")
}

func (s *Server) verifyExternalJWT(c OAuthConfig, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, err
	}
	if hdr.Alg == "" || hdr.Alg == "none" || strings.HasPrefix(hdr.Alg, "HS") {
		return nil, errors.New("unsupported token algorithm")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	check := func(force bool) (bool, error) {
		keys, anon, err := s.oidcKeys(c, hdr.Kid, force)
		if err != nil {
			return false, err
		}
		if k, ok := keys[hdr.Kid]; ok && hdr.Kid != "" {
			return verifyJWTSignature(hdr.Alg, k, signed, sig), nil
		}
		for _, k := range anon {
			if verifyJWTSignature(hdr.Alg, k, signed, sig) {
				return true, nil
			}
		}
		if hdr.Kid == "" {
			for _, k := range keys {
				if verifyJWTSignature(hdr.Alg, k, signed, sig) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	ok, err := check(false)
	if err == nil && !ok {
		ok, err = check(true)
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("token signature does not match the identity provider's keys")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}
	now := float64(time.Now().Unix())
	if exp, ok := claims["exp"].(float64); !ok || now > exp+60 {
		return nil, errors.New("token expired")
	}
	if nbf, ok := claims["nbf"].(float64); ok && now+60 < nbf {
		return nil, errors.New("token not valid yet")
	}
	if d, err := s.oidcDiscover(c); err == nil && d.Issuer != "" {
		if iss, _ := claims["iss"].(string); strings.TrimRight(iss, "/") != strings.TrimRight(d.Issuer, "/") {
			return nil, errors.New("token issuer does not match")
		}
	}
	if c.Audience != "" {
		auds := claimStrings(claims["aud"])
		azp, _ := claims["azp"].(string)
		if !slices.Contains(auds, c.Audience) && azp != c.Audience {
			return nil, errors.New("token audience does not match")
		}
	}
	return claims, nil
}

func claimValue(claims map[string]any, path string) any {
	var cur any = claims
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

func claimStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ' ' })
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (s *Server) claimsToAuth(c OAuthConfig, claims map[string]any) (string, *ExternalAuth, error) {
	name := ""
	for _, k := range []string{c.UsernameClaim, "preferred_username", "username", "email", "sub"} {
		if k == "" {
			continue
		}
		if v, ok := claimValue(claims, k).(string); ok && v != "" {
			name = v
			break
		}
	}
	if !validName.MatchString(name) {
		return "", nil, fmt.Errorf("token user name %q cannot be used", name)
	}
	var re *regexp.Regexp
	if c.GroupNameRegex != "" {
		re, _ = regexp.Compile(c.GroupNameRegex)
	}
	var groups []string
	for _, g := range claimStrings(claimValue(claims, firstNonEmpty(c.GroupsClaim, "groups"))) {
		g = strings.TrimSpace(g)
		if i := strings.LastIndex(g, "/"); i >= 0 {
			g = g[i+1:]
		}
		if re != nil {
			m := re.FindStringSubmatch(g)
			if m == nil {
				continue
			}
			if len(m) > 1 {
				g = m[1]
			}
		}
		if c.GroupPrefix != "" && !strings.HasPrefix(g, c.GroupPrefix) {
			continue
		}
		if validGroup.MatchString(g) && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	if c.AddAnonymous {
		groups = append(groups, s.dir.AnonGroup())
	}
	admin := c.AdminGroup != "" && containsFold(groups, c.AdminGroup)
	if c.AdminClaimName != "" {
		v := claimValue(claims, c.AdminClaimName)
		if c.AdminClaimValue == "" {
			b, _ := v.(bool)
			admin = admin || b
		} else if slices.Contains(claimStrings(v), c.AdminClaimValue) {
			admin = true
		}
	}
	callsign := ""
	if c.CallsignClaim != "" {
		callsign, _ = claimValue(claims, c.CallsignClaim).(string)
	}
	return name, &ExternalAuth{Groups: groups, Admin: admin, Callsign: callsign}, nil
}

func (s *Server) oidcIdentity(token string) (*Identity, error) {
	c := s.Config().OAuth
	if !c.usable() || s.oidc == nil {
		return nil, errors.New("external sign-in is off")
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	s.oidc.mu.Lock()
	if hit, ok := s.oidc.idCache[key]; ok && time.Now().Before(hit.expires) {
		s.oidc.mu.Unlock()
		return hit.id, nil
	}
	s.oidc.mu.Unlock()
	claims, err := s.verifyExternalJWT(c, token)
	if err != nil {
		return nil, err
	}
	name, res, err := s.claimsToAuth(c, claims)
	if err != nil {
		return nil, err
	}
	id, err := s.dir.externalLogin(name, res)
	if err != nil {
		return nil, err
	}
	id.Via = "oauth"
	exp := time.Now().Add(5 * time.Minute)
	if e, ok := claims["exp"].(float64); ok && time.Unix(int64(e), 0).Before(exp) {
		exp = time.Unix(int64(e), 0)
	}
	s.oidc.mu.Lock()
	if len(s.oidc.idCache) > 5000 {
		now := time.Now()
		for k, v := range s.oidc.idCache {
			if now.After(v.expires) {
				delete(s.oidc.idCache, k)
			}
		}
	}
	s.oidc.idCache[key] = oidcCached{id: id, expires: exp}
	s.oidc.mu.Unlock()
	return id, nil
}

func (s *Server) tokenIdentity(token string) (*Identity, error) {
	if c, err := s.parseOAuthToken(token); err == nil {
		return s.dir.Identity(c.Sub, "oauth")
	}
	return s.oidcIdentity(token)
}

const oidcStateCookie = "golangtakserver_oidc"

func (s *Server) signBlob(v []byte) string {
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write(v)
	return base64.RawURLEncoding.EncodeToString(v) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) openBlob(t string) ([]byte, bool) {
	a, b, ok := strings.Cut(t, ".")
	if !ok {
		return nil, false
	}
	v, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(b)
	m := hmac.New(sha256.New, s.tokenKey)
	m.Write(v)
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return nil, false
	}
	return v, true
}

func (s *Server) oidcRedirectURI(r *http.Request) string {
	if u := s.Config().OAuth.RedirectURI; u != "" {
		return u
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/login/redirect"
}

func (s *Server) loginAuth(w http.ResponseWriter, r *http.Request) {
	c := s.Config().OAuth
	if !c.usable() || c.ClientID == "" {
		writeText(w, http.StatusNotFound, "sign-in with an identity provider is not configured")
		return
	}
	d, err := s.oidcDiscover(c)
	if err != nil || d.Authorization == "" {
		s.log.Warn("identity provider unavailable", "err", err)
		writeText(w, http.StatusBadGateway, "the identity provider is unavailable")
		return
	}
	next := localPath(r.URL.Query().Get("next"))
	st := map[string]any{"state": NewSecret(16), "verifier": NewSecret(32), "next": next, "exp": time.Now().Add(10 * time.Minute).Unix()}
	raw, _ := json.Marshal(st)
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: s.signBlob(raw), Path: "/login", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: 600}) // #nosec G124 nosemgrep -- Secure whenever the request arrived over TLS
	sum := sha256.Sum256([]byte(st["verifier"].(string)))
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", s.oidcRedirectURI(r))
	q.Set("scope", firstNonEmpty(c.Scope, "openid profile email"))
	q.Set("state", st["state"].(string))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(d.Authorization, "?") {
		sep = "&"
	}
	http.Redirect(w, r, d.Authorization+sep+q.Encode(), http.StatusFound)
}

func (s *Server) oidcTokenRequest(c OAuthConfig, form url.Values) (map[string]any, error) {
	d, err := s.oidcDiscover(c)
	if err != nil {
		return nil, err
	}
	if d.Token == "" {
		return nil, errors.New("the identity provider has no token endpoint")
	}
	form.Set("client_id", c.ClientID)
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	resp, err := s.oidcHTTPClient(c).PostForm(d.Token, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := map[string]any{}
	json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %s: %v", resp.Status, out["error_description"])
	}
	return out, nil
}

func (s *Server) loginRedirect(w http.ResponseWriter, r *http.Request) {
	c := s.Config().OAuth
	q := r.URL.Query()
	ck, err := r.Cookie(oidcStateCookie)
	if err != nil {
		writeText(w, http.StatusBadRequest, "the sign-in took too long or cookies are blocked; try again")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/login", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil}) // #nosec G124 nosemgrep -- clearing the cookie
	raw, ok := s.openBlob(ck.Value)
	var st struct {
		State    string `json:"state"`
		Verifier string `json:"verifier"`
		Next     string `json:"next"`
		Exp      int64  `json:"exp"`
	}
	if !ok || json.Unmarshal(raw, &st) != nil || st.State != q.Get("state") || time.Now().Unix() > st.Exp {
		writeText(w, http.StatusBadRequest, "state did not match request")
		return
	}
	if e := q.Get("error"); e != "" {
		writeText(w, http.StatusUnauthorized, "the identity provider refused the sign-in: "+e)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {s.oidcRedirectURI(r)}, "code_verifier": {st.Verifier}}
	tok, err := s.oidcTokenRequest(c, form)
	if err != nil {
		s.log.Warn("identity provider token exchange failed", "err", err)
		writeText(w, http.StatusBadGateway, "the identity provider did not issue a token")
		return
	}
	var id *Identity
	for _, k := range []string{"access_token", "id_token"} {
		if t, _ := tok[k].(string); looksLikeJWT(t) {
			if id, err = s.oidcIdentity(t); err == nil {
				break
			}
		}
	}
	if id == nil {
		s.log.Warn("identity provider token rejected", "err", err)
		writeText(w, http.StatusUnauthorized, "the identity provider's token was not accepted")
		return
	}
	u, ok := s.dir.User(id.Name)
	if !ok {
		writeText(w, http.StatusUnauthorized, "no account")
		return
	}
	s.startSession(w, r, u)
	s.log.Info("dashboard sign-in with identity provider", "user", u.Name, "remote", requestIP(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	continuePage.Execute(w, localPath(st.Next))
}

var continuePage = template.Must(template.New("continue").Parse(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={{.}}"><title>Signing in</title><a href="{{.}}">Continue</a>`))

func redirectLocal(w http.ResponseWriter, r *http.Request, target string, code int) {
	http.Redirect(w, r, localPath(target), code)
}

func localPath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	return next
}

func (s *Server) loginRefresh(w http.ResponseWriter, r *http.Request) {
	redirectLocal(w, r, "/login/auth?next="+url.QueryEscape(localPath(r.URL.Query().Get("next"))), http.StatusFound)
}

func (s *Server) loginAuthServer(w http.ResponseWriter, r *http.Request) {
	c := s.Config().OAuth
	if !c.usable() {
		writeText(w, http.StatusOK, "")
		return
	}
	writeText(w, http.StatusOK, firstNonEmpty(c.Name, "Identity provider"))
}

func (s *Server) loginOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	c := s.Config().OAuth
	if c.usable() {
		if d, err := s.oidcDiscover(c); err == nil && len(d.raw) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write(d.raw)
			return
		}
	}
	base := "https://" + r.Host
	if r.TLS == nil {
		base = "http://" + r.Host
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": base, "token_endpoint": base + "/oauth/token", "grant_types_supported": []string{"password", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
	})
}

func (s *Server) loginLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		s.dir.EndSession(ck.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil}) // #nosec G124 nosemgrep -- clearing the cookie
	c := s.Config().OAuth
	if c.usable() {
		if d, err := s.oidcDiscover(c); err == nil && d.EndSession != "" {
			q := url.Values{"client_id": {c.ClientID}, "post_logout_redirect_uri": {strings.TrimSuffix(s.oidcRedirectURI(r), "/login/redirect") + "/"}}
			http.Redirect(w, r, d.EndSession+"?"+q.Encode(), http.StatusFound)
			return
		}
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) tokenAccess(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || id.Anon {
		writeText(w, http.StatusUnauthorized, "sign in first")
		return
	}
	tok, c := s.signOAuthToken(id.Name, oauthTTL)
	s.oidc.record(c, "access", false)
	w.Header().Set("Cache-Control", "no-store")
	writeText(w, http.StatusOK, tok)
}

func (s *Server) tokenCallsign(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || id.Anon {
		writeText(w, http.StatusUnauthorized, "sign in first")
		return
	}
	u, _ := s.dir.User(id.Name)
	writeText(w, http.StatusOK, firstNonEmpty(u.Callsign, id.Name))
}

func (s *Server) martiTokens(w http.ResponseWriter, r *http.Request) {
	expired := boolParam(r, "expired")
	now := time.Now()
	out := []map[string]any{}
	list := s.oidc.issued.All()
	slices.SortFunc(list, func(a, b issuedToken) int { return b.Issued.Compare(a.Issued) })
	for _, t := range list {
		if t.Expires.Before(now) != expired {
			continue
		}
		out = append(out, map[string]any{"clientId": firstNonEmpty(t.ClientID, "TAK Server"), "token": t.JTI, "username": t.User, "expires": isoTime(t.Expires), "issued": isoTime(t.Issued), "refresh": t.Refresh})
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.oauth.TokenApi$TokenResult", out))
}

func (s *Server) jtiOf(v string) string {
	if looksLikeJWT(v) {
		parts := strings.Split(v, ".")
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var c oauthClaims
			if json.Unmarshal(b, &c) == nil && c.Jti != "" {
				return c.Jti
			}
		}
	}
	return v
}

func (s *Server) martiTokenRevoke(w http.ResponseWriter, r *http.Request) {
	list := splitList(firstNonEmpty(r.PathValue("tokens"), r.PathValue("token")))
	n := 0
	for _, t := range list {
		if s.oidc.revoke(s.jtiOf(t)) {
			n++
		}
	}
	if n == 0 {
		writeJSON(w, http.StatusNotFound, s.envelope("error", "no such token"))
		return
	}
	s.log.Info("oauth tokens revoked", "count", n, "by", identityOf(r).Name)
	w.WriteHeader(http.StatusOK)
}
