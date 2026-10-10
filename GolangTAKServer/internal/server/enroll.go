package server

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
)

func (s *Server) martiTLSConfig(w http.ResponseWriter, r *http.Request) {
	ca := s.pki.CA.Cert
	org := "TAK"
	unit := "TAK"
	if len(ca.Subject.Organization) > 0 {
		org = ca.Subject.Organization[0]
	}
	if len(ca.Subject.OrganizationalUnit) > 0 {
		unit = ca.Subject.OrganizationalUnit[0]
	}
	body := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns2:certificateConfig xmlns="http://bbn.com/marti/xml/config" xmlns:ns2="com.bbn.marti.config"><nameEntries><nameEntry name="O" value="` +
		xmlEscapeASCII(org) + `"/><nameEntry name="OU" value="` + xmlEscapeASCII(unit) + `"/></nameEntries></ns2:certificateConfig>`
	writeXML(w, http.StatusOK, body)
}

func (s *Server) signFromRequest(w http.ResponseWriter, r *http.Request) (*x509.Certificate, bool) {
	id := identityOf(r)
	if id == nil || id.Anon || id.Name == "" {
		challenge(w, "sign in with your user name and password")
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeText(w, http.StatusBadRequest, "could not read the certificate request")
		return nil, false
	}
	csr, err := pki.ParseCSR(body)
	if err != nil {
		s.log.Warn("bad certificate request", "user", id.Name, "remote", requestIP(r), "err", err)
		writeText(w, http.StatusBadRequest, "invalid certificate request: "+err.Error())
		return nil, false
	}
	if cn := csr.Subject.CommonName; cn != "" && !strings.EqualFold(cn, id.Name) {
		s.log.Warn("certificate request name does not match the signed-in user", "user", id.Name, "cn", cn)
		writeText(w, http.StatusBadRequest, "the certificate request common name must be your user name")
		return nil, false
	}
	q := r.URL.Query()
	clientUID := firstNonEmpty(q.Get("clientUid"), q.Get("clientUID"))
	channels := q.Get("version") != "" || s.Config().Channels
	validity := time.Duration(s.Config().Certificates.ClientDays) * 24 * time.Hour
	cert, err := s.pki.issueClientCSR(id.Name, csr, channels, validity)
	if err != nil {
		s.log.Error("certificate signing failed", "user", id.Name, "err", err)
		writeText(w, http.StatusInternalServerError, "certificate signing failed")
		return nil, false
	}
	if err := s.dir.RecordCert(id.Name, newCertRecord(cert, clientUID, "enroll")); err != nil {
		s.log.Error("could not record issued certificate", "user", id.Name, "err", err)
	}
	if id.Via == "token" && id.TokenID != "" {
		s.dir.ConsumeToken(id.TokenID)
	}
	s.log.Info("certificate enrolled", "user", id.Name, "client", clientUID, "remote", requestIP(r), "expires", cert.NotAfter.Format("2006-01-02"))
	return cert, true
}

func (s *Server) martiSignClientV2(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.signFromRequest(w, r)
	if !ok {
		return
	}
	signed := pki.PEMBody(cert)
	ca := pki.PEMBody(s.pki.CA.Cert)
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/xml") && !strings.Contains(accept, "json") {
		writeXML(w, http.StatusOK, `<?xml version="1.0" encoding="UTF-8"?><enrollment><signedCert>`+signed+`</signedCert><ca>`+ca+`</ca></enrollment>`)
		return
	}
	body, _ := json.Marshal(map[string]string{"signedCert": signed, "ca0": ca})
	if accept == "text/plain" {
		w.Header().Set("Content-Type", "text/plain")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (s *Server) martiSignClientV1(w http.ResponseWriter, r *http.Request) {
	cert, ok := s.signFromRequest(w, r)
	if !ok {
		return
	}
	p12, err := pki.EncodeTrustStore([]*x509.Certificate{cert, s.pki.CA.Cert}, s.Config().Certificates.Password, "signedCert", "ca0")
	if err != nil {
		writeText(w, http.StatusInternalServerError, "could not build key store")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(p12)
}

func (s *Server) martiMakeKeyStore(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	if id == nil || id.Anon {
		challenge(w, "sign in with your user name and password")
		return
	}
	cn := firstNonEmpty(r.URL.Query().Get("cn"), id.Name)
	if !strings.EqualFold(cn, id.Name) && !id.Admin {
		writeText(w, http.StatusForbidden, "you may only create certificates for yourself")
		return
	}
	if _, ok := s.dir.User(cn); !ok {
		writeText(w, http.StatusNotFound, "no such user")
		return
	}
	data, cert, err := s.pki.NewClientP12(cn, time.Duration(s.Config().Certificates.ClientDays)*24*time.Hour, s.Config().Channels)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "could not create certificate")
		return
	}
	s.dir.RecordCert(cn, newCertRecord(cert, r.URL.Query().Get("clientUid"), "keystore"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFileName(cn)+`.p12"`)
	w.Write(data) // #nosec G705 -- PKCS#12 download
}

func (s *Server) martiEnrollmentProfile(w http.ResponseWriter, r *http.Request) {
	data, err := s.buildProfile(r, true, r.URL.Query().Get("clientUid"), 0)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "could not build enrollment profile")
		return
	}
	if data == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Write(data)
}

func (s *Server) martiConnectionProfile(w http.ResponseWriter, r *http.Request) {
	secago := int64(0)
	if v := r.URL.Query().Get("syncSecago"); v != "" {
		if n, err := parseInt64(v); err == nil && n > 0 {
			secago = n
		}
	}
	data, err := s.buildProfile(r, false, r.URL.Query().Get("clientUid"), secago)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "could not build connection profile")
		return
	}
	if data == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Write(data)
}

func (s *Server) martiToolProfile(w http.ResponseWriter, r *http.Request) {
	tool := strings.TrimSpace(r.PathValue("tool"))
	q := r.URL.Query()
	clientUID := q.Get("clientUid")
	var cut time.Time
	if n, err := parseInt64(q.Get("syncSecago")); err == nil && n > 0 {
		cut = time.Now().Add(-time.Duration(n) * time.Second)
	}
	var groups []string
	if c := s.hub.ByUID(clientUID); c != nil {
		groups = s.dir.Names(c.OutMask())
	} else if id := identityOf(r); id != nil {
		groups = s.identityGroups(id)
	}
	var prefs []prefEntry
	var files []zipEntry
	for _, it := range s.profiles.Items() {
		if !strings.EqualFold(it.Tool, tool) || (it.ClientUID != "" && it.ClientUID != clientUID) || (it.Group != "" && !containsFold(groups, it.Group)) || (!cut.IsZero() && it.Updated.Before(cut)) {
			continue
		}
		if it.Kind == "file" {
			if data, err := s.res.blobs.Read(it.Hash); err == nil {
				files = append(files, zipEntry{safeFileName(it.Name), data})
			}
			continue
		}
		prefs = append(prefs, prefEntry{Key: it.Key, Class: javaClass(it.Class), Value: it.Value})
	}
	if len(prefs) == 0 && len(files) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	folder := "profile-" + safeFileName(tool)
	var entries []zipEntry
	if len(prefs) > 0 {
		entries = append(entries, zipEntry{folder + "/preference.pref", []byte(prefsXML(map[string][]prefEntry{"com.atakmap.app_preferences": prefs}, []string{"com.atakmap.app_preferences"}))})
	}
	for _, f := range files {
		entries = append(entries, zipEntry{folder + "/" + f.Name, f.Data})
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	data, err := buildZip(append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifestXML(cot.NewUID(), s.Config().Name+" "+tool+" profile", true, names))}}, entries...))
	if err != nil {
		writeText(w, http.StatusInternalServerError, "could not build the profile")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="profile.zip"`)
	w.Write(data)
}
