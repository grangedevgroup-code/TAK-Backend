package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

type ExternalCAConfig struct {
	Mode     string   `json:"mode,omitempty"`
	URL      string   `json:"url,omitempty"`
	Template string   `json:"template,omitempty"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	Command  string   `json:"command,omitempty"`
	Args     []string `json:"args,omitempty"`
	ChainPEM string   `json:"chainPem,omitempty"`
	Insecure bool     `json:"insecure,omitempty"`
}

func (c ExternalCAConfig) enabled() bool { return c.Mode == "certsrv" || c.Mode == "command" }

type externalCA struct {
	mu    sync.Mutex
	cfg   ExternalCAConfig
	chain []*x509.Certificate
}

var reqIDRe = regexp.MustCompile(`certnew\.cer\?ReqID=(\d+)`)

func (p *PKI) SetExternal(cfg ExternalCAConfig) {
	p.extMu.Lock()
	defer p.extMu.Unlock()
	if !cfg.enabled() {
		p.ext = nil
		return
	}
	e := &externalCA{cfg: cfg}
	if certs, err := pki.ParseCertPEM([]byte(cfg.ChainPEM)); err == nil {
		e.chain = certs
	}
	p.ext = e
}

func (p *PKI) external() *externalCA {
	p.extMu.RLock()
	defer p.extMu.RUnlock()
	return p.ext
}

func (p *PKI) ClientPool() *x509.CertPool {
	pool := p.CA.Pool()
	if e := p.external(); e != nil {
		e.mu.Lock()
		for _, c := range e.chain {
			pool.AddCert(c)
		}
		e.mu.Unlock()
	}
	return pool
}

func (p *PKI) issueClientKey(cn string, key crypto.Signer, channels bool, validity time.Duration) (*x509.Certificate, []*x509.Certificate, error) {
	e := p.external()
	if e == nil {
		cert, err := p.CA.IssueClient(cn, key.Public(), channels, validity)
		return cert, []*x509.Certificate{p.CA.Cert}, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return nil, nil, err
	}
	return e.sign(der, cn)
}

func (p *PKI) issueClientCSR(cn string, csr *x509.CertificateRequest, channels bool, validity time.Duration) (*x509.Certificate, error) {
	e := p.external()
	if e == nil {
		return p.CA.IssueClient(cn, csr.PublicKey, channels, validity)
	}
	cert, _, err := e.sign(csr.Raw, cn)
	return cert, err
}

func (e *externalCA) sign(csrDER []byte, cn string) (*x509.Certificate, []*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	var out []byte
	var err error
	switch e.cfg.Mode {
	case "certsrv":
		out, err = e.certsrv(ctx, csrPEM)
	case "command":
		out, err = e.command(ctx, csrPEM, cn)
	default:
		return nil, nil, errors.New("no external certificate authority is configured")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("external certificate authority: %w", err)
	}
	certs, err := pki.ParseCertPEM(out)
	if err != nil || len(certs) == 0 {
		return nil, nil, errors.New("external certificate authority returned no certificate")
	}
	leaf := certs[0]
	csr, _ := x509.ParseCertificateRequest(csrDER)
	if csr != nil && !pki.PublicKeysEqual(leaf.PublicKey, csr.PublicKey) {
		return nil, nil, errors.New("external certificate authority returned a certificate for a different key")
	}
	e.mu.Lock()
	if len(certs) > 1 {
		e.chain = certs[1:]
	}
	chain := append([]*x509.Certificate(nil), e.chain...)
	e.mu.Unlock()
	return leaf, chain, nil
}

func (e *externalCA) client() *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: e.cfg.Insecure, MinVersion: tls.VersionTLS12}}}
}

func (e *externalCA) do(ctx context.Context, method, u string, body io.Reader, ctype string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if e.cfg.Username != "" {
		req.SetBasicAuth(e.cfg.Username, e.cfg.Password)
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("the CA refused the user name or password (Basic authentication must be enabled on certsrv)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return b, nil
}

func (e *externalCA) certsrv(ctx context.Context, csrPEM []byte) ([]byte, error) {
	base := strings.TrimRight(e.cfg.URL, "/")
	if !strings.HasSuffix(strings.ToLower(base), "/certsrv") {
		base += "/certsrv"
	}
	form := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {string(csrPEM)},
		"CertAttrib":       {"CertificateTemplate:" + firstNonEmpty(e.cfg.Template, "User")},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
		"ThumbPrint":       {""},
	}
	page, err := e.do(ctx, http.MethodPost, base+"/certfnsh.asp", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}
	m := reqIDRe.FindSubmatch(page)
	if m == nil {
		text := string(page)
		switch {
		case strings.Contains(text, "Certificate Pending"):
			return nil, errors.New("the request is waiting for approval on the CA; approve it or use a template that issues automatically")
		case strings.Contains(text, "Denied"):
			return nil, errors.New("the CA denied the request; check the template name and its permissions")
		}
		return nil, errors.New("unexpected answer from certsrv (no certificate link)")
	}
	cert, err := e.do(ctx, http.MethodGet, base+"/certnew.cer?ReqID="+string(m[1])+"&Enc=b64", nil, "")
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	needChain := len(e.chain) == 0
	e.mu.Unlock()
	if needChain {
		if ca, err := e.do(ctx, http.MethodGet, base+"/certnew.cer?ReqID=CACert&Renewal=-1&Enc=b64", nil, ""); err == nil {
			cert = append(append(cert, '\n'), ca...)
		}
	}
	return cert, nil
}

func (e *externalCA) command(ctx context.Context, csrPEM []byte, cn string) ([]byte, error) {
	if e.cfg.Command == "" {
		return nil, errors.New("no signing command is set")
	}
	cmd := exec.CommandContext(ctx, e.cfg.Command, e.cfg.Args...)
	cmd.Stdin = bytes.NewReader(csrPEM)
	cmd.Env = append(os.Environ(), "GOLANGTAKSERVER_CN="+cn)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
