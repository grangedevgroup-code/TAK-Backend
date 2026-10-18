package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

func (s *Server) fedHTTPSPort() int {
	cfg := s.Config()
	switch p := cfg.Federation.HTTPSPort; {
	case p > 0:
		return p
	case p < 0:
		return 0
	}
	if cfg.Federation.Enabled && cfg.Ports.Federation > 0 {
		return 8444
	}
	return 0
}

func (s *Server) clientContentURL(hash string) string {
	cfg := s.Config()
	scheme, port := "https", cfg.Ports.HTTPS
	if port <= 0 {
		scheme, port = "http", cfg.Ports.HTTP
	}
	return scheme + "://" + net.JoinHostPort(HostForURL(cfg.Address), strconv.Itoa(port)) + "/Marti/sync/content?hash=" + url.QueryEscape(hash)
}

func isFileShare(e *cot.Event) bool {
	return e != nil && e.Type == "b-f-t-r" && e.D("fileshare") != nil
}

func (s *Server) federateFromTLS(r *http.Request) (*fedPolicy, *x509.Certificate) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil
	}
	cert := r.TLS.PeerCertificates[0]
	name := cert.Subject.CommonName
	if cert.Issuer.CommonName != "" {
		name += " (" + cert.Issuer.CommonName + ")"
	}
	return s.fedPolicyFor(certFingerprint(cert), name, chainCAFingerprint(r.TLS.VerifiedChains), nil), cert
}

func (s *Server) startFederationHTTPS() error {
	port := s.fedHTTPSPort()
	if port <= 0 || !s.Config().Federation.Enabled {
		return nil
	}
	ln, err := s.listenTCP(port)
	if err != nil {
		if s.Config().Federation.HTTPSPort == 0 {
			s.log.Warn("federation file transfer port unavailable; federated data packages over version 1 need it", "port", port, "err", err)
			return nil
		}
		return err
	}
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"http/1.1"},
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /Marti/sync/missionquery", s.fedMissionQuery)
	mux.HandleFunc("POST /Marti/sync/missionupload", s.fedMissionUpload)
	mux.HandleFunc("PUT /Marti/sync/missionupload", s.fedMissionUpload)
	mux.HandleFunc("GET /Marti/sync/content", s.fedContent)
	hs := &http.Server{Handler: s.recoverer(mux), ReadHeaderTimeout: 20 * time.Second, MaxHeaderBytes: 1 << 20, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return s.ctx }, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	s.lmu.Lock()
	s.https = append(s.https, hs)
	s.lmu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		hs.Serve(tls.NewListener(ln, base))
	}()
	s.log.Info("federation file transfer port listening", "port", port)
	return nil
}

func (s *Server) fedMissionQuery(w http.ResponseWriter, r *http.Request) {
	pol, _ := s.federateFromTLS(r)
	if pol == nil || pol.disabled {
		writeText(w, http.StatusForbidden, "federate not allowed")
		return
	}
	res, ok := s.res.Get(r.URL.Query().Get("hash"))
	if !ok || !s.res.blobs.Exists(res.Hash) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	writeText(w, http.StatusOK, s.clientContentURL(res.UID))
}

func (s *Server) fedMissionUpload(w http.ResponseWriter, r *http.Request) {
	pol, _ := s.federateFromTLS(r)
	if pol == nil || pol.disabled {
		writeText(w, http.StatusForbidden, "federate not allowed")
		return
	}
	q := r.URL.Query()
	hash := strings.ToLower(strings.TrimSpace(q.Get("hash")))
	name := firstNonEmpty(q.Get("filename"), hash)
	if name != "" && !strings.Contains(name, ".") {
		name += ".zip"
	}
	if s.fileBlocked(name, nil) {
		writeText(w, http.StatusForbidden, "file type blocked by the federation file filter")
		return
	}
	def := Resource{Name: name, MIMEType: "application/x-zip-compressed", Keywords: []string{"missionpackage"}, Tool: "public",
		Submitter: "federate:" + pol.name, Groups: pol.in, Package: true, UID: hash}
	res, code, err := s.storeUpload(w, r, def)
	if err != nil {
		writeText(w, code, "upload failed: "+err.Error())
		return
	}
	if hash != "" && res.Hash != hash {
		s.res.Delete(res.UID)
		writeText(w, http.StatusBadRequest, "the uploaded file does not match its hash")
		return
	}
	if data, err := s.res.blobs.Read(res.Hash); err == nil && s.fileBlocked(name, data) {
		s.res.Delete(res.UID)
		writeText(w, http.StatusForbidden, "file type blocked by the federation file filter")
		return
	}
	s.log.Info("federated data package received", "federate", pol.name, "name", res.Name, "size", res.Size)
	writeText(w, http.StatusOK, s.clientContentURL(res.UID))
}

func (s *Server) fedContent(w http.ResponseWriter, r *http.Request) {
	pol, _ := s.federateFromTLS(r)
	if pol == nil || pol.disabled {
		writeText(w, http.StatusForbidden, "federate not allowed")
		return
	}
	res, ok := s.res.Get(firstNonEmpty(r.URL.Query().Get("hash"), r.URL.Query().Get("uid")))
	if !ok || (len(res.Groups) > 0 && !s.dir.Mask(res.Groups).Intersects(s.dir.Mask(pol.out))) {
		writeText(w, http.StatusNotFound, "File not found")
		return
	}
	f, err := s.res.blobs.Open(res.Hash)
	if err != nil {
		writeText(w, http.StatusNotFound, "File content missing")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", firstNonEmpty(res.MIMEType, "application/octet-stream"))
	http.ServeContent(w, r, res.Name, st.ModTime(), f)
}

func (s *Server) fedHTTPClient() *http.Client {
	trust := s.federationTrust()
	tcfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 -- the chain is verified against the federation trust store in VerifyConnection; federates are addressed by IP
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return s.pki.ServerCert(), nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the federate presented no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			chains, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: trust, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			if err != nil {
				return err
			}
			return s.revocationErr(chains)
		},
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{TLSClientConfig: tcfg, ForceAttemptHTTP2: false}}
}

func (s *Server) pushV1Package(c *Client, host string, m *Message) {
	out := func(msg *Message) {
		msg.fedReady = true
		c.Send(msg)
	}
	fs := m.Event.D("fileshare")
	hash := strings.ToLower(fs.Attr("sha256"))
	res, ok := s.res.Get(hash)
	port := s.fedHTTPSPort()
	if port <= 0 {
		port = 8444
	}
	if !ok || hash == "" || host == "" {
		out(m)
		return
	}
	data, err := s.res.blobs.Read(res.Hash)
	if err != nil {
		out(m)
		return
	}
	if s.fileBlocked(res.Name, data) {
		s.log.Info("data package not federated: blocked by the file filter", "name", res.Name)
		return
	}
	hc := s.fedHTTPClient()
	base := "https://" + net.JoinHostPort(host, strconv.Itoa(port))
	target := ""
	if resp, err := hc.Get(base + "/Marti/sync/missionquery?hash=" + url.QueryEscape(hash)); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			target = strings.TrimSpace(string(body))
		}
	}
	if target == "" {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		part, _ := mw.CreateFormFile("assetfile", res.Name)
		part.Write(data)
		mw.Close()
		u := base + "/Marti/sync/missionupload?hash=" + url.QueryEscape(hash) + "&filename=" + url.QueryEscape(res.Name)
		resp, err := hc.Post(u, mw.FormDataContentType(), &buf)
		if err != nil {
			s.log.Warn("could not send the data package to the federate", "federate", c.Name, "err", err)
			out(m)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			s.log.Warn("the federate refused the data package", "federate", c.Name, "status", resp.Status)
			out(m)
			return
		}
		target = strings.TrimSpace(string(body))
	}
	e := m.Event.Clone()
	e.D("fileshare").SetAttr("senderUrl", target)
	nm := NewMessage(e, m.Source, m.Groups)
	nm.Everyone, nm.Hops, nm.NoReplay = m.Everyone, m.Hops, true
	out(nm)
}

type packageDests struct {
	Callsigns []string `json:"callsigns"`
	UIDs      []string `json:"uids"`
}

func (s *Server) packageAnnounceROL(c *Client, m *Message) (takproto.ROL, bool, bool) {
	fs := m.Event.D("fileshare")
	hash := strings.ToLower(fs.Attr("sha256"))
	res, ok := s.res.Get(hash)
	if !ok {
		return takproto.ROL{}, false, true
	}
	data, err := s.res.blobs.Read(res.Hash)
	if err != nil || len(data) > s.Config().Limits.MaxMessageBytes-64<<10 {
		return takproto.ROL{}, false, true
	}
	if s.fileBlocked(res.Name, data) {
		s.log.Info("data package not federated: blocked by the file filter", "name", res.Name)
		return takproto.ROL{}, false, false
	}
	d := packageDests{Callsigns: []string{}, UIDs: []string{}}
	for _, dest := range m.Event.Dests() {
		if dest.UID != "" {
			d.UIDs = append(d.UIDs, dest.UID)
		} else if dest.Callsign != "" {
			d.Callsigns = append(d.Callsigns, dest.Callsign)
		}
	}
	dj, _ := json.Marshal(d)
	size, _ := strconv.Atoi(fs.Attr("sizeInBytes"))
	if size == 0 {
		size = len(data)
	}
	rd := map[string]any{"sha256": res.Hash, "senderUid": string(dj), "name": firstNonEmpty(fs.Attr("name"), res.Name), "filename": firstNonEmpty(fs.Attr("filename"), res.Name),
		"senderUrl": "", "tsStored": time.Now().UnixMilli(), "size": size, "senderCallsign": fs.Attr("senderCallsign"), "localPath": ""}
	groups, ok := s.outboundGroups(c, m, 1)
	if !ok {
		return takproto.ROL{}, false, false
	}
	cfg := s.Config()
	maxHops := int64(cfg.Federation.MaxHops)
	if p := c.fedPol(); p != nil {
		maxHops = int64(p.maxHops)
	}
	rol := takproto.ROL{Program: "announce package\n" + rolJSON(rd) + ";", Payload: []takproto.Blob{{Data: data, Filename: res.Name}}, Groups: groups,
		Provenance: []takproto.Provenance{{ServerID: cfg.NodeID, ServerName: cfg.Name}}, MaxHops: maxHops, CurrentHops: 1}
	return rol, true, false
}

func (s *Server) rolPackageAnnounce(src *Client, op string, params []byte, payload []takproto.Blob, groups []string) {
	if op != "announce" {
		return
	}
	var rd struct {
		Sha256         string `json:"sha256"`
		SenderUID      string `json:"senderUid"`
		Name           string `json:"name"`
		Filename       string `json:"filename"`
		SenderCallsign string `json:"senderCallsign"`
		Size           int    `json:"size"`
	}
	if json.Unmarshal(params, &rd) != nil || rd.Sha256 == "" {
		return
	}
	hash := strings.ToLower(rd.Sha256)
	name := firstNonEmpty(rd.Filename, rd.Name, hash+".zip")
	if _, ok := s.res.Get(hash); !ok {
		if len(payload) == 0 || int64(len(payload[0].Data)) > s.uploadLimit() {
			s.log.Warn("federated data package announced without its file", "from", src.Name, "name", name)
			return
		}
		data := payload[0].Data
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != hash {
			s.log.Warn("federated data package does not match its hash", "from", src.Name, "name", name)
			return
		}
		if s.fileBlocked(name, data) {
			s.log.Info("federated data package blocked by the file filter", "from", src.Name, "name", name)
			return
		}
		got, err := s.res.Blobs().PutBytes(data)
		if err != nil {
			return
		}
		res := Resource{UID: got, Hash: got, Name: name, MIMEType: "application/x-zip-compressed", Size: int64(len(data)), Keywords: []string{"missionpackage"},
			Tool: "public", Submitter: "federate:" + src.Name, Submitted: time.Now().UTC(), Groups: groups, Expiration: -1, Package: true}
		if err := s.res.Put(res); err != nil {
			return
		}
	}
	var d packageDests
	json.Unmarshal([]byte(rd.SenderUID), &d)
	e := cot.New(cot.NewUID(), "b-f-t-r", "h-e", 100*time.Second)
	e.Point.Hae, e.Point.Ce, e.Point.Le = 9999999, 9999999, 9999999
	e.Detail.AddNew("fileshare", "sha256", hash, "senderUid", "", "name", firstNonEmpty(rd.Name, name), "filename", name,
		"senderUrl", s.clientContentURL(hash), "sizeInBytes", strconv.Itoa(max(rd.Size, 0)), "senderCallsign", rd.SenderCallsign)
	var dests []cot.Dest
	for _, u := range d.UIDs {
		dests = append(dests, cot.Dest{UID: u})
	}
	for _, cs := range d.Callsigns {
		dests = append(dests, cot.Dest{Callsign: cs})
	}
	if len(dests) > 0 {
		e.SetDests(dests)
	}
	msg := NewMessage(e, src, s.dir.Mask(groups))
	msg.NoReplay = true
	s.hub.Publish(msg)
	s.log.Info("federated data package announced", "from", src.Name, "name", name, "to", fmt.Sprint(len(dests)))
}
