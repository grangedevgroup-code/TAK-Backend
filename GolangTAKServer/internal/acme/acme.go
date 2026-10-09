package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type Client struct {
	Directory string
	Key       *ecdsa.PrivateKey
	Email     string
	HTTP      *http.Client

	dir   directory
	kid   string
	nonce string
}

type Problem struct {
	Status int
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (p *Problem) Error() string { return fmt.Sprintf("acme: %s (%s)", p.Detail, p.Type) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (c *Client) jwk() map[string]string {
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64(pad32(c.Key.X)), "y": b64(pad32(c.Key.Y))}
}

func (c *Client) Thumbprint() string {
	k := c.jwk()
	canon := `{"crv":"` + k["crv"] + `","kty":"` + k["kty"] + `","x":"` + k["x"] + `","y":"` + k["y"] + `"}`
	sum := sha256.Sum256([]byte(canon))
	return b64(sum[:])
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) init(ctx context.Context) error {
	if c.dir.NewNonce != "" {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Directory, nil)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme directory: HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&c.dir)
}

func (c *Client) fetchNonce(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	c.nonce = resp.Header.Get("Replay-Nonce")
	if c.nonce == "" {
		return errors.New("acme: no nonce")
	}
	return nil
}

func (c *Client) post(ctx context.Context, url string, payload any, out any) (*http.Response, []byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if c.nonce == "" {
			if err := c.fetchNonce(ctx); err != nil {
				return nil, nil, err
			}
		}
		prot := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": url}
		if c.kid != "" {
			prot["kid"] = c.kid
		} else {
			prot["jwk"] = c.jwk()
		}
		pb, _ := json.Marshal(prot)
		var body string
		if payload != nil {
			b, _ := json.Marshal(payload)
			body = b64(b)
		}
		signing := b64(pb) + "." + body
		sum := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, c.Key, sum[:])
		if err != nil {
			return nil, nil, err
		}
		jws, _ := json.Marshal(map[string]string{"protected": b64(pb), "payload": body, "signature": b64(append(pad32(r), pad32(s)...))})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jws))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := c.client().Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		c.nonce = resp.Header.Get("Replay-Nonce")
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode >= 400 {
			p := &Problem{Status: resp.StatusCode}
			json.Unmarshal(data, p)
			if p.Type == "urn:ietf:params:acme:error:badNonce" {
				c.nonce = ""
				continue
			}
			return resp, data, p
		}
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return resp, data, err
			}
		}
		return resp, data, nil
	}
	return nil, nil, errors.New("acme: the server kept rejecting nonces")
}

func (c *Client) Register(ctx context.Context) error {
	if err := c.init(ctx); err != nil {
		return err
	}
	if c.kid != "" {
		return nil
	}
	acct := map[string]any{"termsOfServiceAgreed": true}
	if c.Email != "" {
		acct["contact"] = []string{"mailto:" + c.Email}
	}
	resp, _, err := c.post(ctx, c.dir.NewAccount, acct, nil)
	if err != nil {
		return err
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		return errors.New("acme: the account has no location")
	}
	return nil
}

type order struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type authorization struct {
	Status     string `json:"status"`
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string   `json:"type"`
		URL    string   `json:"url"`
		Token  string   `json:"token"`
		Status string   `json:"status"`
		Error  *Problem `json:"error"`
	} `json:"challenges"`
}

type Solver func(token, keyAuth string) (cleanup func())

func (c *Client) poll(ctx context.Context, url string, out any, done func() (bool, error)) error {
	delay := time.Second
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, _, err := c.post(ctx, url, nil, out); err != nil {
			return err
		}
		ok, err := done()
		if err != nil || ok {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("acme: timed out waiting for the certificate authority")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 10*time.Second)
	}
}

func (c *Client) Obtain(ctx context.Context, domains []string, certKey crypto.Signer, solve Solver) ([]byte, error) {
	if err := c.Register(ctx); err != nil {
		return nil, err
	}
	var ids []map[string]string
	for _, d := range domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	var o order
	resp, _, err := c.post(ctx, c.dir.NewOrder, map[string]any{"identifiers": ids}, &o)
	if err != nil {
		return nil, err
	}
	orderURL := resp.Header.Get("Location")
	for _, az := range o.Authorizations {
		var a authorization
		if _, _, err := c.post(ctx, az, nil, &a); err != nil {
			return nil, err
		}
		if a.Status == "valid" {
			continue
		}
		var curl, token string
		for _, ch := range a.Challenges {
			if ch.Type == "http-01" {
				curl, token = ch.URL, ch.Token
			}
		}
		if curl == "" {
			return nil, fmt.Errorf("acme: no http-01 challenge for %s", a.Identifier.Value)
		}
		cleanup := solve(token, token+"."+c.Thumbprint())
		_, _, err := c.post(ctx, curl, map[string]any{}, nil)
		if err == nil {
			err = c.poll(ctx, az, &a, func() (bool, error) {
				switch a.Status {
				case "valid":
					return true, nil
				case "invalid":
					for _, ch := range a.Challenges {
						if ch.Error != nil {
							return false, fmt.Errorf("acme: %s failed validation: %s", a.Identifier.Value, ch.Error.Detail)
						}
					}
					return false, fmt.Errorf("acme: %s failed validation", a.Identifier.Value)
				}
				return false, nil
			})
		}
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			return nil, err
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, certKey)
	if err != nil {
		return nil, err
	}
	if _, _, err := c.post(ctx, o.Finalize, map[string]string{"csr": b64(csr)}, &o); err != nil {
		return nil, err
	}
	if err := c.poll(ctx, orderURL, &o, func() (bool, error) {
		switch o.Status {
		case "valid":
			return true, nil
		case "invalid":
			return false, errors.New("acme: the order became invalid")
		}
		return false, nil
	}); err != nil {
		return nil, err
	}
	_, pemData, err := c.post(ctx, o.Certificate, nil, nil)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(pemData), "BEGIN CERTIFICATE") {
		return nil, errors.New("acme: the certificate download was not PEM")
	}
	return pemData, nil
}
