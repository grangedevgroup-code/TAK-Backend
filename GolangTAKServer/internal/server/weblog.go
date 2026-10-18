package server

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type WebConfig struct {
	JSONLogs         bool                `json:"jsonLogs,omitempty"`
	AccessLog        bool                `json:"accessLog,omitempty"`
	AuditLog         bool                `json:"auditLog,omitempty"`
	CORSOrigins      []string            `json:"corsOrigins,omitempty"`
	CORSCredentials  bool                `json:"corsCredentials,omitempty"`
	HSTS             bool                `json:"hsts,omitempty"`
	TLSMinVersion    string              `json:"tlsMinVersion,omitempty"`
	TLSCiphers       []string            `json:"tlsCiphers,omitempty"`
	MaxHTTPHeaderKB  int                 `json:"maxHttpHeaderKb,omitempty"`
	CustomHeaders    []string            `json:"customHeaders,omitempty"`
	SessionMinutes   int                 `json:"sessionMinutes,omitempty"`
	DisableDashboard bool                `json:"disableDashboard,omitempty"`
	ContentDir       string              `json:"contentDir,omitempty"`
	ContentAccess    []ContentAccessRule `json:"contentAccess,omitempty"`
}

type webLogs struct {
	access io.WriteCloser
	audit  io.WriteCloser
}

func (s *Server) openWebLogs() {
	s.weblogs = &webLogs{
		access: NewLogBuffer(filepath.Join(s.DataDir, "logs", "access.log"), nil),
		audit:  NewLogBuffer(filepath.Join(s.DataDir, "logs", "audit.log"), nil),
	}
}

func (s *Server) closeWebLogs() {
	if s.weblogs != nil {
		s.weblogs.access.Close()
		s.weblogs.audit.Close()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func originAllowed(origins []string, origin string) bool {
	for _, o := range origins {
		if o == "*" || strings.EqualFold(strings.TrimRight(o, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

func (s *Server) webPolicy(w http.ResponseWriter, r *http.Request) bool {
	wc := s.Config().Web
	if wc.HSTS && r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	for _, h := range wc.CustomHeaders {
		if k, v, ok := strings.Cut(h, ":"); ok && strings.TrimSpace(k) != "" {
			w.Header().Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	if origin := r.Header.Get("Origin"); origin != "" && len(wc.CORSOrigins) > 0 && originAllowed(wc.CORSOrigins, origin) {
		allow := origin
		if slices.Contains(wc.CORSOrigins, "*") && !wc.CORSCredentials {
			allow = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", allow)
		w.Header().Add("Vary", "Origin")
		if wc.CORSCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", firstNonEmpty(r.Header.Get("Access-Control-Request-Headers"), "Authorization, Content-Type"))
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return false
		}
	}
	if wc.DisableDashboard && listenerName(r) != "api" && (r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/")) {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (s *Server) logAccess(r *http.Request, rec *statusRecorder, start time.Time) {
	if s.weblogs == nil || !s.Config().Web.AccessLog {
		return
	}
	user := "-"
	if id := identityOf(r); id != nil && id.Name != "" {
		user = id.Name
	}
	line := requestIP(r) + " " + user + " [" + start.UTC().Format("02/Jan/2006:15:04:05 -0700") + "] \"" + r.Method + " " + r.URL.RequestURI() + " " + r.Proto + "\" " +
		strconv.Itoa(max(rec.status, 200)) + " " + strconv.FormatInt(rec.bytes, 10) + " " + strconv.FormatInt(time.Since(start).Milliseconds(), 10) + "ms " + listenerName(r) + "\n"
	s.weblogs.access.Write([]byte(line))
}

var auditPrefixes = []string{"/Marti/sync/", "/Marti/api/missions", "/Marti/api/cot", "/Marti/api/files", "/Marti/api/resources", "/Marti/api/user-management",
	"/Marti/api/ldap-user-management", "/Marti/api/certadmin", "/Marti/api/tls/", "/Marti/api/federat", "/Marti/api/outgoingconnections", "/Marti/api/datafeeds",
	"/Marti/api/retention", "/Marti/api/token", "/Marti/ExportMissionKML", "/Marti/TracksKML", "/Marti/CotQueryServlet", "/api/users", "/api/settings", "/api/files",
	"/api/missions", "/api/cot", "/api/certs", "/api/tokens", "/api/backup", "/api/kml", "/api/tracks"}

func (s *Server) audit(r *http.Request, id *Identity, status int) {
	if s.weblogs == nil || !s.Config().Web.AuditLog {
		return
	}
	if !slices.ContainsFunc(auditPrefixes, func(p string) bool { return strings.HasPrefix(r.URL.Path, p) }) {
		return
	}
	user, via := "anonymous", ""
	if id != nil {
		user, via = firstNonEmpty(id.Name, "anonymous"), id.Via
	}
	b, _ := json.Marshal(map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "user": user, "via": via, "remote": requestIP(r), "method": r.Method,
		"path": r.URL.Path, "query": r.URL.RawQuery, "status": status, "listener": listenerName(r)})
	s.weblogs.audit.Write(append(b, '\n'))
}

var tlsCipherNames = func() map[string]uint16 {
	m := map[string]uint16{}
	for _, c := range tls.CipherSuites() {
		m[c.Name] = c.ID
	}
	for _, c := range tls.InsecureCipherSuites() {
		m[c.Name] = c.ID
	}
	return m
}()

func (s *Server) tuneTLS(c *tls.Config) *tls.Config {
	wc := s.Config().Web
	switch strings.ToUpper(strings.TrimPrefix(strings.ToUpper(wc.TLSMinVersion), "TLSV")) {
	case "1.3":
		c.MinVersion = tls.VersionTLS13
	case "1.2", "":
		if c.MinVersion < tls.VersionTLS12 {
			c.MinVersion = tls.VersionTLS12
		}
	}
	if len(wc.TLSCiphers) > 0 {
		var ids []uint16
		for _, name := range wc.TLSCiphers {
			if id, ok := tlsCipherNames[strings.TrimSpace(name)]; ok {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			c.CipherSuites = ids
		}
	}
	return c
}

func validWebConfig(wc WebConfig) error {
	for _, name := range wc.TLSCiphers {
		if _, ok := tlsCipherNames[strings.TrimSpace(name)]; !ok {
			return &configError{"unknown TLS cipher suite " + name}
		}
	}
	switch strings.ToUpper(strings.TrimPrefix(strings.ToUpper(wc.TLSMinVersion), "TLSV")) {
	case "", "1.2", "1.3":
	default:
		return &configError{"tlsMinVersion must be 1.2 or 1.3"}
	}
	return nil
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

func (s *Server) maxHeaderBytes() int {
	if kb := s.Config().Web.MaxHTTPHeaderKB; kb > 0 {
		return kb << 10
	}
	return 1 << 20
}
