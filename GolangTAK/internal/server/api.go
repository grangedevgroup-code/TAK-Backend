package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/qr"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/websocket"
)

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	return nil
}

func apiError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	id, err := s.dir.CheckPassword(requestIP(r), body.Username, body.Password)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, ErrThrottled) {
			status = http.StatusTooManyRequests
		}
		s.log.Warn("dashboard sign-in failed", "user", body.Username, "remote", requestIP(r))
		apiError(w, status, err)
		return
	}
	u, _ := s.dir.User(id.Name)
	if s.startLogin(w, r, u) {
		return
	}
	s.finishLogin(w, r, u)
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.dir.EndSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	cfg := s.Config()
	out := map[string]any{"user": id.Name, "admin": id.Admin, "groups": s.dir.Names(id.Out.Union(id.In)), "via": id.Via,
		"server": cfg.Name, "version": s.Version, "tileUrl": cfg.TileURL}
	if sess := sessionOf(r); sess != nil {
		out["csrf"] = sess.CSRF
	}
	if u, _, err := ReadInitialPassword(s.DataDir); err == nil && strings.EqualFold(u, id.Name) {
		out["initialPassword"] = true
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiMePassword(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := s.dir.CheckPassword(requestIP(r), id.Name, body.Current); err != nil {
		apiError(w, http.StatusForbidden, errors.New("the current password is not correct"))
		return
	}
	if err := s.dir.SetPassword(id.Name, body.Password); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.forgetInitialPassword(id.Name)
	s.log.Info("password changed", "user", id.Name, "remote", requestIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	host, _ := os.Hostname()
	ca := s.pki.CA.Cert
	leaf := s.pki.ServerLeaf()
	filesBytes, filesCount := s.res.blobs.Usage()
	histBytes, histDays := s.history.Usage()
	kinds := map[string]int{}
	for _, c := range s.hub.Clients() {
		if !c.Relay {
			kinds[c.Kind]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": cfg.Name, "version": s.Version, "address": cfg.Address, "hostname": host,
		"os": runtime.GOOS, "arch": runtime.GOARCH, "go": runtime.Version(), "cpus": runtime.NumCPU(),
		"started": s.Started.UTC(), "uptimeSeconds": int64(time.Since(s.Started).Seconds()),
		"clients": s.hub.Count(), "clientsByKind": kinds, "users": s.dir.UserCount(), "devices": len(s.devices.All()),
		"missions": len(s.missions.All()), "files": filesCount, "filesBytes": filesBytes, "videos": len(s.videos.All()),
		"historyBytes": histBytes, "historyDays": histDays, "historyDropped": s.history.Dropped.Load(),
		"events": s.hub.Events.Load(), "delivered": s.hub.Delivered.Load(), "bytesOut": s.hub.Bytes.Load(),
		"cached": len(s.hub.Cached()), "emergencies": len(s.hub.Emergencies()), "pendingChats": len(s.PendingChats()),
		"memoryBytes": ms.Alloc, "goroutines": runtime.NumGoroutine(), "dataDir": s.DataDir,
		"ports": cfg.Ports, "allowAnonymous": cfg.AllowAnonymous, "protobuf": cfg.Protobuf, "mesh": cfg.Mesh,
		"caSubject": ca.Subject.CommonName, "caFingerprint": pki.Fingerprint(ca), "caExpires": ca.NotAfter,
		"serverCertExpires": leaf.NotAfter, "serverNames": append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...),
		"peers": s.peerStatus(), "federation": s.federationStatus(), "feeds": s.feedStatus(), "meshtastic": s.meshStatus(),
	})
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func (s *Server) connectHosts() []string {
	cfg := s.Config()
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[strings.ToLower(h)] {
			seen[strings.ToLower(h)] = true
			out = append(out, h)
		}
	}
	add(cfg.Address)
	add(cfg.ACMEDomain)
	for _, n := range cfg.ExtraNames {
		add(n)
	}
	for _, ip := range LocalIPs() {
		add(ip)
	}
	return out
}

func (s *Server) apiConnect(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	host := firstNonEmpty(r.URL.Query().Get("host"), cfg.Address)
	tcpPort := cfg.Ports.TCP
	if tcpPort == 0 {
		tcpPort = cfg.Ports.TCPAlt
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": cfg.Name, "host": host, "hosts": s.connectHosts(), "ports": cfg.Ports,
		"itak":               s.ITAKString(host, false),
		"itakTcp":            s.ITAKString(host, true),
		"tlsConnect":         host + ":" + itoa(cfg.Ports.TLS) + ":ssl",
		"tcpConnect":         host + ":" + itoa(tcpPort) + ":tcp",
		"enrollUrl":          "https://" + HostForURL(host) + ":" + itoa(cfg.Ports.Enroll),
		"dashboardUrl":       "https://" + HostForURL(host) + ":" + itoa(cfg.Ports.Enroll) + "/",
		"websocketUrl":       "ws://" + HostForURL(host) + ":" + itoa(cfg.Ports.WebSocket) + "/",
		"caFingerprint":      pki.Fingerprint(s.pki.CA.Cert),
		"truststorePassword": cfg.Certificates.Password,
		"allowAnonymous":     cfg.AllowAnonymous,
	})
}

func (s *Server) canActFor(id *Identity, user string) bool {
	return id != nil && !id.Anon && (id.Admin || strings.EqualFold(id.Name, user))
}

func (s *Server) apiEnrollToken(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		User  string `json:"user"`
		Host  string `json:"host"`
		Hours int    `json:"hours"`
		Uses  int    `json:"uses"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	body.User = firstNonEmpty(body.User, id.Name)
	if !s.canActFor(id, body.User) {
		apiError(w, http.StatusForbidden, errors.New("you can only create enrollment codes for yourself"))
		return
	}
	if body.Hours <= 0 || body.Hours > 24*30 {
		body.Hours = 24
	}
	secret, tok, err := s.dir.CreateToken(body.User, "enroll", "enrollment code", time.Duration(body.Hours)*time.Hour, body.Uses)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	host := firstNonEmpty(body.Host, s.Config().Address)
	uri := s.ATAKEnrollURI(host, body.User, secret)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": body.User, "token": secret, "expires": tok.Expires, "atak": uri, "itak": s.ITAKString(host, false),
		"atakQR": qrSVG(uri), "itakQR": qrSVG(s.ITAKString(host, false)),
	})
}

func qrSVG(text string) string {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	return c.SVG(6, 4)
}

func (s *Server) apiQR(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" || len(data) > 2000 {
		apiError(w, http.StatusBadRequest, errors.New("data parameter is required (up to 2000 characters)"))
		return
	}
	c, err := qr.Encode(data, qr.M)
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if r.URL.Query().Get("format") == "png" {
		w.Header().Set("Content-Type", "image/png")
		w.Write(c.PNG(8, 4))
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte(c.SVG(6, 4)))
}

func (s *Server) apiPackage(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	kind := PackageKind(firstNonEmpty(q.Get("type"), "cert"))
	user := firstNonEmpty(q.Get("user"), id.Name)
	if kind != PackageTCP && !s.canActFor(id, user) {
		apiError(w, http.StatusForbidden, errors.New("you can only download your own connection package"))
		return
	}
	data, name, err := s.BuildPackage(kind, user, firstNonEmpty(q.Get("host"), s.Config().Address))
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("connection package downloaded", "type", kind, "user", user, "by", id.Name, "remote", requestIP(r))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(data)
}

type downloadLink struct {
	kind    PackageKind
	user    string
	host    string
	expires time.Time
	uses    int
}

func (s *Server) apiPackageLink(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Type    string `json:"type"`
		User    string `json:"user"`
		Host    string `json:"host"`
		Minutes int    `json:"minutes"`
		Plain   bool   `json:"plain"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	body.User = firstNonEmpty(body.User, id.Name)
	if !s.canActFor(id, body.User) {
		apiError(w, http.StatusForbidden, errors.New("you can only create links for yourself"))
		return
	}
	if body.Minutes <= 0 || body.Minutes > 7*24*60 {
		body.Minutes = 30
	}
	u := s.packageLink(PackageKind(firstNonEmpty(body.Type, "cert")), body.User, body.Host, body.Minutes, body.Plain)
	writeJSON(w, http.StatusOK, map[string]any{"url": u, "import": ImportURI(u), "qr": qrSVG(ImportURI(u)), "expires": time.Now().Add(time.Duration(body.Minutes) * time.Minute)})
}

func (s *Server) packageLink(kind PackageKind, user, host string, minutes int, plain bool) string {
	cfg := s.Config()
	host = firstNonEmpty(host, cfg.Address)
	tok := NewSecret(24)
	s.linkMu.Lock()
	for k, l := range s.links {
		if time.Now().After(l.expires) {
			delete(s.links, k)
		}
	}
	s.links[tok] = &downloadLink{kind: kind, user: user, host: host, expires: time.Now().Add(time.Duration(minutes) * time.Minute), uses: 1}
	s.linkMu.Unlock()
	scheme, port := "https", cfg.Ports.Enroll
	if plain && cfg.Ports.HTTP > 0 {
		scheme, port = "http", cfg.Ports.HTTP
	}
	return scheme + "://" + HostForURL(host) + ":" + itoa(port) + "/dl/" + tok
}

func (s *Server) downloadByLink(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	s.linkMu.Lock()
	l, ok := s.links[tok]
	if ok && (time.Now().After(l.expires) || l.uses <= 0) {
		delete(s.links, tok)
		ok = false
	}
	if ok {
		l.uses--
		if l.uses <= 0 {
			delete(s.links, tok)
		}
	}
	s.linkMu.Unlock()
	if !ok {
		writeText(w, http.StatusNotFound, "this download link has expired or was already used")
		return
	}
	data, name, err := s.BuildPackage(l.kind, l.user, l.host)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("connection package downloaded by link", "user", l.user, "remote", requestIP(r))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(data)
}

func (s *Server) apiCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="golangtak-ca.pem"`)
	w.Write(s.pki.CA.CertPEM)
}

func (s *Server) apiTrustStore(w http.ResponseWriter, r *http.Request) {
	t, err := s.pki.TrustStore()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", `attachment; filename="golangtak-truststore.p12"`)
	w.Write(t)
}

func (s *Server) apiClients(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []ClientView{}
	for _, c := range s.hub.Clients() {
		if !id.Admin && !s.visibleTo(id, c.InMask()) {
			continue
		}
		out = append(out, s.hub.View(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiKick(w http.ResponseWriter, r *http.Request) {
	idv, _ := strconv.ParseUint(r.PathValue("id"), 10, 64)
	c := s.hub.Client(idv)
	if c == nil {
		apiError(w, http.StatusNotFound, errors.New("no such client"))
		return
	}
	if c.Internal() {
		apiError(w, http.StatusBadRequest, errors.New("this is a built-in listener of the server and cannot be disconnected"))
		return
	}
	s.log.Info("client disconnected by administrator", "remote", c.Remote, "by", identityOf(r).Name)
	c.Close()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiDevices(w http.ResponseWriter, r *http.Request) {
	live := map[string]bool{}
	for _, c := range s.hub.Clients() {
		if uid := c.UID(); uid != "" {
			live[uid] = true
		}
	}
	out := []Device{}
	for _, d := range s.devices.All() {
		if live[d.UID] {
			d.LastStatus = "Connected"
		} else if d.LastStatus == "Connected" {
			d.LastStatus = "Disconnected"
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiDeviceDelete(w http.ResponseWriter, r *http.Request) {
	s.devices.Delete(r.PathValue("uid"))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type eventView struct {
	UID      string    `json:"uid"`
	Type     string    `json:"type"`
	Callsign string    `json:"callsign"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Hae      float64   `json:"hae"`
	Course   *float64  `json:"course,omitempty"`
	Speed    *float64  `json:"speed,omitempty"`
	Time     time.Time `json:"time"`
	Stale    time.Time `json:"stale"`
	Team     string    `json:"team,omitempty"`
	Remarks  string    `json:"remarks,omitempty"`
	Source   string    `json:"source,omitempty"`
	Chat     string    `json:"chat,omitempty"`
	To       string    `json:"to,omitempty"`
	XML      string    `json:"xml,omitempty"`

	Shape   *shapeView        `json:"shape,omitempty"`
	Medevac map[string]string `json:"medevac,omitempty"`
	Image   bool              `json:"image,omitempty"`
}

func viewOf(m *Message, withXML bool) eventView {
	e := m.Event
	v := eventView{UID: e.UID, Type: e.Type, Callsign: e.Callsign(), Lat: e.Point.Lat, Lon: e.Point.Lon, Hae: e.Point.Hae, Time: e.Time, Stale: e.Stale, Remarks: e.Remarks()}
	v.Team, _ = e.Team()
	if tr := e.D("track"); tr != nil {
		if c, err := strconv.ParseFloat(tr.Attr("course"), 64); err == nil && c >= 0 && c <= 360 {
			v.Course = &c
		}
		if sp, err := strconv.ParseFloat(tr.Attr("speed"), 64); err == nil && sp >= 0 && sp < 1e5 {
			v.Speed = &sp
		}
	}
	v.Shape = shapeOf(e)
	v.Medevac = medevacOf(e)
	if n := e.D("image"); n != nil && strings.TrimSpace(n.Text) != "" {
		v.Image = true
	}
	if m.Source != nil {
		v.Source = m.Source.Kind + " " + m.Source.Remote
	} else {
		v.Source = "server"
	}
	if e.IsChat() {
		if ch := e.D("__chat"); ch != nil {
			v.Callsign = firstNonEmpty(ch.Attr("senderCallsign"), v.Callsign)
			v.To = ch.Attr("chatroom")
		}
		v.Chat = e.Remarks()
	}
	if withXML {
		v.XML = string(m.XML())
	}
	return v
}

func (s *Server) apiLatest(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	q := r.URL.Query()
	prefix := q.Get("type")
	withXML := boolParam(r, "xml")
	out := []eventView{}
	for _, m := range s.hub.Cached() {
		if !m.Everyone && !id.Admin && !s.visibleTo(id, m.Groups) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(m.Event.Type, prefix) {
			continue
		}
		if uid := q.Get("uid"); uid != "" && m.Event.UID != uid {
			continue
		}
		out = append(out, viewOf(m, withXML))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, until := timeWindow(r)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100000 {
		limit = 1000
	}
	events := s.history.Query(historyQuery{UID: q.Get("uid"), Type: q.Get("type"), Start: since, End: until, Limit: limit, Can: s.historyFilter(identityOf(r))})
	if q.Get("format") == "xml" {
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><events>`)
		for _, e := range events {
			b.Write(e.XML())
		}
		b.WriteString("</events>")
		writeXML(w, http.StatusOK, b.String())
		return
	}
	out := make([]eventView, 0, len(events))
	for _, e := range events {
		out = append(out, viewOf(&Message{Event: e}, boolParam(r, "xml")))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiTracks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	can := s.historyFilter(identityOf(r))
	since := time.Now().Add(-time.Hour)
	if v, err := strconv.Atoi(q.Get("minutes")); err == nil && v > 0 {
		since = time.Now().Add(-time.Duration(v) * time.Minute)
	}
	uids := splitList(q.Get("uid"))
	if len(uids) == 0 {
		for _, m := range s.hub.Cached() {
			if m.Event.IsSA() {
				uids = append(uids, m.Event.UID)
			}
		}
	}
	out := map[string]any{}
	for _, uid := range uids {
		cs, pts := s.history.Track(uid, since, can)
		if len(pts) > 0 {
			out[uid] = map[string]any{"callsign": cs, "points": pts}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiKML(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, until := timeWindow(r)
	uids := splitList(q.Get("uid"))
	if len(uids) == 0 {
		for _, d := range s.devices.All() {
			uids = append(uids, d.UID)
		}
	}
	w.Header().Set("Content-Type", "application/vnd.google-earth.kml+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="tracks.kml"`)
	w.Write([]byte(s.tracksKML(uids, since, until, s.historyFilter(identityOf(r)))))
}

func (s *Server) martiExportKML(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	r.ParseForm()
	q := r.Form
	var start, end time.Time
	if v := q.Get("startTime"); v != "" {
		start, _ = cot.ParseTime(v)
	}
	if v := q.Get("endTime"); v != "" {
		end, _ = cot.ParseTime(v)
	}
	uids := splitList(q.Get("uid"))
	if len(uids) == 0 {
		for _, d := range s.devices.All() {
			uids = append(uids, d.UID)
		}
	}
	w.Header().Set("Content-Type", "application/vnd.google-earth.kml+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="export.kml"`)
	w.Write([]byte(s.tracksKML(uids, start, end, s.historyFilter(identityOf(r)))))
}

func (s *Server) apiPostCoT(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.Config().Limits.MaxMessageBytes)))
	if err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	everyone := id.Admin && r.URL.Query().Get("groups") == "all"
	groups := id.In
	if g := splitList(r.URL.Query().Get("groups")); len(g) > 0 && !everyone {
		if !id.Admin {
			for _, name := range g {
				if !slices.Contains(s.dir.Names(id.In), name) {
					apiError(w, http.StatusForbidden, errors.New("you are not in group "+name))
					return
				}
			}
		}
		groups = s.dir.Mask(g)
	}
	src := s.apiClient(id)
	fr := takproto.NewReader(bytes.NewReader(body), s.Config().Limits.MaxMessageBytes)
	n := 0
	var uids []string
	for {
		f, err := fr.Next()
		if err != nil {
			break
		}
		var e *cot.Event
		if f.Proto {
			e, err = takproto.UnmarshalEvent(f.Data)
		} else {
			e, err = cot.Parse(f.Data)
		}
		if err != nil {
			continue
		}
		m := NewMessage(e, src, groups)
		m.Everyone = everyone
		s.hub.Identify(src, m)
		s.hub.Publish(m)
		n++
		uids = append(uids, e.UID)
	}
	if n == 0 {
		apiError(w, http.StatusBadRequest, errors.New("no valid CoT events in the request body"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"published": n, "uids": uids})
}

func (s *Server) apiClient(id *Identity) *Client {
	s.apiMu.Lock()
	defer s.apiMu.Unlock()
	if s.apiSrc != nil && !s.apiSrc.IsClosed() {
		return s.apiSrc
	}
	c := s.relayClient(KindAPI, "REST API", "api", nil)
	c.SetIdentity(s.dir.Anonymous())
	c.filter = func(*Message) bool { return false }
	s.hub.Add(c)
	s.apiSrc = c
	return c
}

func (s *Server) apiChat(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		Message string `json:"message"`
		To      string `json:"to"`
		Sender  string `json:"sender"`
	}
	if err := decodeBody(r, &body); err != nil || strings.TrimSpace(body.Message) == "" {
		apiError(w, http.StatusBadRequest, errors.New("message is required"))
		return
	}
	sender := firstNonEmpty(body.Sender, s.Config().Name)
	room, roomID := "All Chat Rooms", "All Chat Rooms"
	var dests []cot.Dest
	if t := strings.TrimSpace(body.To); t != "" && !strings.EqualFold(t, "All Chat Rooms") {
		if c := s.hub.ByUID(t); c != nil {
			room, roomID = c.Callsign(), t
			dests = []cot.Dest{{UID: t}}
		} else if c := s.hub.ByCallsign(t); c != nil {
			room, roomID = t, c.UID()
			dests = []cot.Dest{{Callsign: t}}
		} else if dev, ok := s.devices.ByCallsign(t); ok {
			room, roomID = t, dev.UID
			dests = []cot.Dest{{Callsign: t}}
		} else {
			apiError(w, http.StatusNotFound, errors.New("no contact called "+t))
			return
		}
	}
	e := cot.Chat(s.UID(), sender, room, roomID, body.Message, dests)
	m := NewMessage(e, nil, id.In)
	m.Everyone = id.Admin
	m.NoReplay = true
	s.hub.Publish(m)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uid": e.UID})
}

func (s *Server) apiMarker(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	var body struct {
		UID     string  `json:"uid"`
		Name    string  `json:"name"`
		Type    string  `json:"type"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		Hae     float64 `json:"hae"`
		Remarks string  `json:"remarks"`
		Minutes int     `json:"minutes"`
		Color   string  `json:"color"`
	}
	if err := decodeBody(r, &body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if body.Lat < -90 || body.Lat > 90 || body.Lon < -180 || body.Lon > 180 {
		apiError(w, http.StatusBadRequest, errors.New("latitude or longitude out of range"))
		return
	}
	if body.Minutes <= 0 {
		body.Minutes = 24 * 60
	}
	e := cot.New(firstNonEmpty(body.UID, cot.NewUID()), firstNonEmpty(body.Type, "a-u-G"), "h-g-i-g-o", time.Duration(body.Minutes)*time.Minute)
	e.Point = cot.Point{Lat: body.Lat, Lon: body.Lon, Hae: body.Hae, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(body.Name, "Marker"))
	if body.Remarks != "" {
		e.Detail.AddNew("remarks").Text = body.Remarks
	}
	if body.Color != "" {
		e.Detail.AddNew("color", "argb", body.Color)
	}
	e.Detail.AddNew("link", "uid", s.UID(), "relation", "p-p", "type", "a-f-G-U-C")
	e.Detail.AddNew("archive")
	m := NewMessage(e, nil, id.In)
	m.Everyone = id.Admin
	s.hub.Publish(m)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uid": e.UID})
}

func (s *Server) apiDeleteEvent(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	uid := r.PathValue("uid")
	typ := "a-u-G"
	if m := s.hub.CachedEvent(uid); m != nil {
		typ = m.Event.Type
	}
	e := cot.DeleteFor(uid, typ)
	e.Detail.AddNew("__forcedelete")
	m := NewMessage(e, nil, id.In)
	m.Everyone = id.Admin
	s.hub.Publish(m)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiStream(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	format := r.URL.Query().Get("format")
	sub := s.hub.Subscribe(1024, func(m *Message) bool {
		return m.Everyone || id.Admin || s.visibleTo(id, m.Groups)
	})
	defer s.hub.Unsubscribe(sub)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-done:
			return
		case <-s.ctx.Done():
			conn.Close(websocket.CloseGoingAway, "server stopping")
			return
		case <-ping.C:
			if conn.Ping(nil) != nil {
				return
			}
		case m := <-sub.C:
			conn.SetWriteDeadline(time.Now().Add(20 * time.Second))
			var err error
			if format == "xml" {
				err = conn.WriteText(string(m.XML()))
			} else {
				b, _ := json.Marshal(viewOf(m, format == "full"))
				err = conn.WriteText(string(b))
			}
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 2000 {
		n = 500
	}
	writeJSON(w, http.StatusOK, s.logs.Tail(n))
}

func (s *Server) apiLogStream(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ch, cancel := s.logs.Subscribe()
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		case <-s.ctx.Done():
			return
		case line := <-ch:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if conn.WriteText(line) != nil {
				return
			}
		}
	}
}

func (s *Server) apiEmergencies(w http.ResponseWriter, r *http.Request) {
	out := []eventView{}
	for _, m := range s.hub.Emergencies() {
		out = append(out, viewOf(m, false))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	writeJSON(w, http.StatusOK, out)
}
