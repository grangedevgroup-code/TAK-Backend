package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	ErrRevoked      = errors.New("certificate has been revoked")
	ErrUndetermined = errors.New("certificate revocation status could not be determined")
)

type Config struct {
	CRLFiles  []string
	OCSP      bool
	Responder string
	Strict    bool
}

func (c Config) Enabled() bool { return len(c.CRLFiles) > 0 || c.OCSP }

type crlFile struct {
	path  string
	mtime time.Time
	size  int64
	lists []*x509.RevocationList
}

type cacheEntry struct {
	res   OCSPResult
	err   error
	until time.Time
}

type Checker struct {
	mu       sync.Mutex
	cfg      Config
	files    []*crlFile
	lastStat time.Time
	cache    map[string]cacheEntry
	Client   *http.Client
	Now      func() time.Time
	Skip     func(cert *x509.Certificate) bool
	Warn     func(msg string, args ...any)
}

func New() *Checker {
	return &Checker{cache: map[string]cacheEntry{}, Client: &http.Client{Timeout: 5 * time.Second}, Now: time.Now}
}

func (c *Checker) warn(msg string, args ...any) {
	if c.Warn != nil {
		c.Warn(msg, args...)
	}
}

func ParseCRLs(data []byte) ([]*x509.RevocationList, error) {
	var out []*x509.RevocationList
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "X509 CRL" {
			continue
		}
		l, err := x509.ParseRevocationList(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if len(out) > 0 {
		return out, nil
	}
	l, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}
	return []*x509.RevocationList{l}, nil
}

func loadCRLFile(path string) (*crlFile, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lists, err := ParseCRLs(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &crlFile{path: path, mtime: st.ModTime(), size: st.Size(), lists: lists}, nil
}

func (c *Checker) Configure(cfg Config) []error {
	var errs []error
	var files []*crlFile
	for _, p := range cfg.CRLFiles {
		f, err := loadCRLFile(p)
		if err != nil {
			errs = append(errs, err)
			files = append(files, &crlFile{path: p})
			continue
		}
		files = append(files, f)
	}
	c.mu.Lock()
	c.cfg = Config{CRLFiles: append([]string(nil), cfg.CRLFiles...), OCSP: cfg.OCSP, Responder: cfg.Responder, Strict: cfg.Strict}
	c.files = files
	c.lastStat = c.Now()
	c.cache = map[string]cacheEntry{}
	c.mu.Unlock()
	return errs
}

func (c *Checker) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.Enabled()
}

func (c *Checker) refresh() {
	now := c.Now()
	if now.Sub(c.lastStat) < 30*time.Second {
		return
	}
	c.lastStat = now
	for i, f := range c.files {
		st, err := os.Stat(f.path)
		if err != nil || (st.ModTime().Equal(f.mtime) && st.Size() == f.size) {
			continue
		}
		nf, err := loadCRLFile(f.path)
		if err != nil {
			c.warn("could not reload certificate revocation list", "file", f.path, "err", err)
			continue
		}
		c.files[i] = nf
	}
}

type CRLInfo struct {
	File       string    `json:"file"`
	Issuer     string    `json:"issuer,omitempty"`
	ThisUpdate time.Time `json:"thisUpdate,omitempty"`
	NextUpdate time.Time `json:"nextUpdate,omitempty"`
	Revoked    int       `json:"revoked"`
	Loaded     bool      `json:"loaded"`
}

func (c *Checker) CRLs() []CRLInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []CRLInfo
	for _, f := range c.files {
		if len(f.lists) == 0 {
			out = append(out, CRLInfo{File: f.path})
			continue
		}
		for _, l := range f.lists {
			out = append(out, CRLInfo{File: f.path, Issuer: l.Issuer.String(), ThisUpdate: l.ThisUpdate, NextUpdate: l.NextUpdate, Revoked: len(l.RevokedCertificateEntries), Loaded: true})
		}
	}
	return out
}

func (c *Checker) crlStatus(cert, issuer *x509.Certificate, now time.Time) (determined bool, err error) {
	for _, f := range c.files {
		for _, l := range f.lists {
			if !bytes.Equal(l.RawIssuer, issuer.RawSubject) || l.CheckSignatureFrom(issuer) != nil {
				continue
			}
			for _, e := range l.RevokedCertificateEntries {
				if e.SerialNumber != nil && e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return true, ErrRevoked
				}
			}
			if l.NextUpdate.IsZero() || now.Before(l.NextUpdate) {
				determined = true
			}
		}
	}
	return determined, nil
}

func cacheKey(cert, issuer *x509.Certificate) string {
	return hex.EncodeToString(issuer.RawSubject) + "/" + cert.SerialNumber.Text(16)
}

func (c *Checker) ocspStatus(ctx context.Context, cert, issuer *x509.Certificate, url string) (OCSPResult, error) {
	key := cacheKey(cert, issuer) + "@" + url
	now := c.Now()
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && now.Before(e.until) {
		c.mu.Unlock()
		return e.res, e.err
	}
	client := c.Client
	c.mu.Unlock()
	res, err := c.queryOCSP(ctx, client, cert, issuer, url, now)
	until := now.Add(30 * time.Second)
	if err == nil {
		until = now.Add(time.Hour)
		if !res.NextUpdate.IsZero() && res.NextUpdate.After(now) {
			until = res.NextUpdate
			if cap := now.Add(24 * time.Hour); until.After(cap) {
				until = cap
			}
		}
	}
	c.mu.Lock()
	if len(c.cache) > 10000 {
		c.cache = map[string]cacheEntry{}
	}
	c.cache[key] = cacheEntry{res: res, err: err, until: until}
	c.mu.Unlock()
	return res, err
}

func (c *Checker) queryOCSP(ctx context.Context, client *http.Client, cert, issuer *x509.Certificate, url string, now time.Time) (OCSPResult, error) {
	body, err := CreateRequest(cert, issuer)
	if err != nil {
		return OCSPResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return OCSPResult{}, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := client.Do(req)
	if err != nil {
		return OCSPResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return OCSPResult{}, fmt.Errorf("ocsp: responder returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return OCSPResult{}, err
	}
	return ParseResponse(data, cert, issuer, now)
}

func (c *Checker) checkOne(ctx context.Context, cert, issuer *x509.Certificate) error {
	c.mu.Lock()
	c.refresh()
	cfg := c.cfg
	now := c.Now()
	determined, err := c.crlStatus(cert, issuer, now)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	var ocspErr error
	if cfg.OCSP {
		urls := cert.OCSPServer
		if cfg.Responder != "" {
			urls = []string{cfg.Responder}
		}
		for _, u := range urls {
			res, err := c.ocspStatus(ctx, cert, issuer, u)
			if err != nil {
				ocspErr = err
				continue
			}
			if res.Status == Revoked {
				return ErrRevoked
			}
			if res.Status == Good {
				determined = true
				break
			}
		}
	}
	if !determined && cfg.Strict {
		if ocspErr != nil {
			return fmt.Errorf("%w: %v", ErrUndetermined, ocspErr)
		}
		return ErrUndetermined
	}
	return nil
}

func (c *Checker) CheckChain(ctx context.Context, chain []*x509.Certificate) error {
	for i := 0; i+1 < len(chain); i++ {
		if c.Skip != nil && c.Skip(chain[i]) {
			continue
		}
		if err := c.checkOne(ctx, chain[i], chain[i+1]); err != nil {
			return fmt.Errorf("%s: %w", chain[i].Subject.CommonName, err)
		}
	}
	return nil
}

func (c *Checker) Check(ctx context.Context, chains [][]*x509.Certificate) error {
	if !c.Enabled() || len(chains) == 0 {
		return nil
	}
	var last error
	for _, ch := range chains {
		if last = c.CheckChain(ctx, ch); last == nil {
			return nil
		}
	}
	return last
}
