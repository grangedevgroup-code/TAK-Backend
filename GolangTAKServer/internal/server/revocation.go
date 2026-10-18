package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/revocation"
)

type RevocationConfig struct {
	CRLFiles      []string `json:"crlFiles,omitempty"`
	OCSP          bool     `json:"ocsp,omitempty"`
	OCSPResponder string   `json:"ocspResponder,omitempty"`
	Strict        bool     `json:"strict,omitempty"`
}

func (s *Server) crlPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.DataDir, p)
}

func (s *Server) revocationConfig(rc RevocationConfig) revocation.Config {
	files := make([]string, 0, len(rc.CRLFiles))
	for _, f := range rc.CRLFiles {
		files = append(files, s.crlPath(f))
	}
	return revocation.Config{CRLFiles: files, OCSP: rc.OCSP, Responder: rc.OCSPResponder, Strict: rc.Strict}
}

func (s *Server) initRevocation() {
	s.revoc = revocation.New()
	s.revoc.Warn = s.log.Warn
	s.revoc.Skip = func(c *x509.Certificate) bool {
		if s.pki == nil || s.pki.CA == nil || s.pki.CA.Cert == nil {
			return false
		}
		ca := s.pki.CA.Cert
		return bytes.Equal(c.RawIssuer, ca.RawSubject) && c.CheckSignatureFrom(ca) == nil
	}
	s.applyRevocation(s.Config().Certificates.Revocation)
}

func (s *Server) applyRevocation(rc RevocationConfig) {
	if s.revoc == nil {
		return
	}
	b, _ := json.Marshal(rc)
	s.revocMu.Lock()
	same := string(b) == s.revocSig
	s.revocSig = string(b)
	s.revocMu.Unlock()
	if same {
		return
	}
	for _, err := range s.revoc.Configure(s.revocationConfig(rc)) {
		s.log.Warn("certificate revocation list could not be loaded", "err", err)
	}
	if rc.OCSP || len(rc.CRLFiles) > 0 {
		s.log.Info("certificate revocation checking enabled", "crlFiles", len(rc.CRLFiles), "ocsp", rc.OCSP, "strict", rc.Strict)
	}
}

func (s *Server) revocationErr(chains [][]*x509.Certificate) error {
	if s.revoc == nil || len(chains) == 0 || !s.revoc.Enabled() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := s.revoc.Check(ctx, chains)
	if err != nil {
		s.log.Warn("certificate rejected by revocation check", "err", err)
	}
	return err
}

func (s *Server) validRevocation(rc RevocationConfig) error {
	if rc.OCSPResponder != "" {
		u, err := url.Parse(rc.OCSPResponder)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &configError{"the OCSP responder must be an http or https URL"}
		}
	}
	for _, f := range rc.CRLFiles {
		data, err := os.ReadFile(s.crlPath(f))
		if err != nil {
			return &configError{fmt.Sprintf("certificate revocation list %s could not be read: %v", f, err)}
		}
		if _, err := revocation.ParseCRLs(data); err != nil {
			return &configError{fmt.Sprintf("certificate revocation list %s could not be parsed: %v", f, err)}
		}
	}
	return nil
}

func (s *Server) apiRevocationStatus(w http.ResponseWriter, r *http.Request) {
	rc := s.Config().Certificates.Revocation
	var crls []revocation.CRLInfo
	if s.revoc != nil {
		crls = s.revoc.CRLs()
	}
	if crls == nil {
		crls = []revocation.CRLInfo{}
	}
	files := rc.CRLFiles
	if files == nil {
		files = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"crlFiles": files, "ocsp": rc.OCSP, "ocspResponder": rc.OCSPResponder, "strict": rc.Strict, "crls": crls})
}
