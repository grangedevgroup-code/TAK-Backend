package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fakeIdP(t *testing.T) (*httptest.Server, func(claims map[string]any) string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/tak/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": srv.URL + "/realms/tak", "jwks_uri": srv.URL + "/realms/tak/certs",
			"authorization_endpoint": srv.URL + "/realms/tak/auth", "token_endpoint": srv.URL + "/realms/tak/token",
		})
	})
	mux.HandleFunc("/realms/tak/certs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	sign := func(claims map[string]any) string {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))
		body, _ := json.Marshal(claims)
		signed := hdr + "." + base64.RawURLEncoding.EncodeToString(body)
		sum := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	return srv, sign
}

func TestExternalIdentityProviderTokens(t *testing.T) {
	idp, sign := fakeIdP(t)
	s := newTestServer(t, func(c *Config) {
		c.AllowAnonymous = false
		c.OAuth = OAuthConfig{Enabled: true, Name: "Keycloak", Issuer: idp.URL + "/realms/tak", ClientID: "tak", AdminGroup: "tak-admins", GroupsClaim: "groups", CallsignClaim: "callsign"}
	})
	now := time.Now().Unix()
	good := sign(map[string]any{"iss": idp.URL + "/realms/tak", "sub": "abc", "preferred_username": "medic7", "groups": []string{"/Blue", "/tak-admins"}, "callsign": "MEDIC-7", "exp": now + 300, "iat": now})
	st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/util/isAdmin"), nil, map[string]string{"Authorization": "Bearer " + good})
	if st != 200 || strings.TrimSpace(string(b)) != "true" {
		t.Fatalf("idp admin token: %d %s", st, b)
	}
	u, ok := s.dir.User("medic7")
	if !ok || !u.External || !containsFold(u.In, "Blue") || u.Callsign != "MEDIC-7" {
		t.Fatalf("external user not created from claims: %+v", u)
	}
	expired := sign(map[string]any{"iss": idp.URL + "/realms/tak", "preferred_username": "medic7", "exp": now - 600})
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/util/isAdmin"), nil, map[string]string{"Authorization": "Bearer " + expired}); st != http.StatusUnauthorized {
		t.Fatalf("expired token accepted: %d", st)
	}
	wrongIss := sign(map[string]any{"iss": "https://evil.example", "preferred_username": "medic7", "exp": now + 300})
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/util/isAdmin"), nil, map[string]string{"Authorization": "Bearer " + wrongIss}); st != http.StatusUnauthorized {
		t.Fatalf("foreign issuer accepted: %d", st)
	}
	tampered := good[:len(good)-4] + "AAAA"
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/util/isAdmin"), nil, map[string]string{"Authorization": "Bearer " + tampered}); st != http.StatusUnauthorized {
		t.Fatalf("tampered token accepted: %d", st)
	}
	st, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/login/authserver"), nil, nil)
	if st != 200 || string(b) != "Keycloak" {
		t.Fatalf("authserver: %d %s", st, b)
	}
	req, _ := http.NewRequest("GET", plainURL(s, "/login/auth"), nil)
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, idp.URL+"/realms/tak/auth?") || !strings.Contains(loc, "code_challenge=") {
		t.Fatalf("login redirect: %d %s", resp.StatusCode, loc)
	}
}

func TestOAuthTokenListAndRevoke(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	s.dir.AddUser("pilot", "pilot-password-1", false, nil)
	st, b := doReq(t, http.DefaultClient, "POST", plainURL(s, "/oauth/token"), strings.NewReader("grant_type=password&username=pilot&password=pilot-password-1"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var tok struct {
		Access string `json:"access_token"`
		JTI    string `json:"jti"`
	}
	if st != 200 || json.Unmarshal(b, &tok) != nil || tok.Access == "" {
		t.Fatalf("token: %d %s", st, b)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok.Access}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/me"), nil, bearer); st != 200 {
		t.Fatalf("token not accepted: %d", st)
	}
	st, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/token"), nil, a)
	if st != 200 || !strings.Contains(string(b), tok.JTI) || !strings.Contains(string(b), `"pilot"`) {
		t.Fatalf("token list: %d %s", st, b)
	}
	if st, b := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/Marti/api/token/"+tok.JTI), nil, a); st != 200 {
		t.Fatalf("revoke: %d %s", st, b)
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/me"), nil, bearer); st != http.StatusUnauthorized {
		t.Fatalf("revoked token still accepted: %d", st)
	}
	st, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/token/access"), nil, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("pilot:pilot-password-1"))})
	if st != 200 || !looksLikeJWT(string(b)) {
		t.Fatalf("token/access: %d %s", st, b)
	}
}
