package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
)

type zipEntry struct {
	Name string
	Data []byte
}

func buildZip(entries []zipEntry) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.Name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func manifestXML(uid, name string, onReceiveDelete bool, entries []string) string {
	var b strings.Builder
	b.WriteString(`<MissionPackageManifest version="2"><Configuration>`)
	b.WriteString(`<Parameter name="uid" value="` + xmlEscapeASCII(uid) + `"/>`)
	b.WriteString(`<Parameter name="name" value="` + xmlEscapeASCII(name) + `"/>`)
	if onReceiveDelete {
		b.WriteString(`<Parameter name="onReceiveDelete" value="true"/>`)
	}
	b.WriteString(`</Configuration><Contents>`)
	for _, e := range entries {
		b.WriteString(`<Content ignore="false" zipEntry="` + xmlEscapeASCII(e) + `"/>`)
	}
	b.WriteString(`</Contents></MissionPackageManifest>`)
	return b.String()
}

type prefEntry struct {
	Key   string
	Class string
	Value string
}

func prefString(k, v string) prefEntry { return prefEntry{k, "class java.lang.String", v} }

func prefBool(k string, v bool) prefEntry {
	return prefEntry{k, "class java.lang.Boolean", strconv.FormatBool(v)}
}

func prefInt(k string, v int) prefEntry {
	return prefEntry{k, "class java.lang.Integer", strconv.Itoa(v)}
}

func prefsXML(sections map[string][]prefEntry, order []string) string {
	var b strings.Builder
	b.WriteString("<?xml version='1.0' encoding='ASCII' standalone='yes'?>\n<preferences>\n")
	for _, name := range order {
		b.WriteString(`<preference version="1" name="` + name + `">` + "\n")
		for _, e := range sections[name] {
			b.WriteString(`<entry key="` + xmlEscapeASCII(e.Key) + `" class="` + e.Class + `">` + xmlEscapeASCII(e.Value) + "</entry>\n")
		}
		b.WriteString("</preference>\n")
	}
	b.WriteString("</preferences>\n")
	return b.String()
}

func (s *Server) shortID() string {
	id := s.Config().NodeID
	if len(id) > 6 {
		id = id[:6]
	}
	return id
}

type PackageKind string

const (
	PackageCert   PackageKind = "cert"
	PackageEnroll PackageKind = "enroll"
	PackageTCP    PackageKind = "tcp"
)

func (s *Server) BuildPackage(kind PackageKind, user, host string) ([]byte, string, error) {
	cfg := s.Config()
	if host == "" {
		host = cfg.Address
	}
	name := cfg.Name
	sid := s.shortID()
	trustName := "truststore-" + safeFileName(strings.ToLower(strings.ReplaceAll(name, " ", "-"))) + "-" + sid + ".p12"
	prefName := "golangtak-" + sid + ".pref"
	streams := []prefEntry{prefInt("count", 1), prefString("description0", name), prefBool("enabled0", true)}
	app := []prefEntry{prefBool("displayServerConnectionWidget", true)}
	var entries []zipEntry
	switch kind {
	case PackageTCP:
		port := cfg.Ports.TCP
		if port == 0 {
			port = cfg.Ports.TCPAlt
		}
		if port == 0 {
			return nil, "", fmt.Errorf("plain TCP is turned off on this server")
		}
		streams = append(streams, prefString("connectString0", fmt.Sprintf("%s:%d:tcp", host, port)))
	case PackageEnroll, PackageCert:
		if cfg.Ports.TLS == 0 {
			return nil, "", fmt.Errorf("TLS streaming is turned off on this server")
		}
		trust, err := s.pki.TrustStore()
		if err != nil {
			return nil, "", err
		}
		pw := cfg.Certificates.Password
		streams = append(streams,
			prefString("connectString0", fmt.Sprintf("%s:%d:ssl", host, cfg.Ports.TLS)),
			prefString("caLocation0", "cert/"+trustName),
			prefString("caPassword0", pw))
		app = append(app, prefString("caLocation", "cert/"+trustName), prefString("caPassword", pw))
		entries = append(entries, zipEntry{"certs/" + trustName, trust})
		if kind == PackageEnroll {
			streams = append(streams,
				prefBool("enrollForCertificateWithTrust0", true),
				prefBool("useAuth0", true),
				prefString("cacheCreds0", "Cache credentials"))
			if user != "" {
				streams = append(streams, prefString("username0", user))
			}
		} else {
			if user == "" {
				return nil, "", fmt.Errorf("a user name is required")
			}
			if _, ok := s.dir.User(user); !ok {
				return nil, "", ErrNoUser
			}
			p12, cert, err := s.pki.NewClientP12(user, time.Duration(cfg.Certificates.ClientDays)*24*time.Hour, cfg.Channels)
			if err != nil {
				return nil, "", err
			}
			if err := s.dir.RecordCert(user, CertRecord{Serial: pki.SerialHex(cert), Created: time.Now().UTC(), Expires: cert.NotAfter, Source: "package"}); err != nil {
				return nil, "", err
			}
			userFile := safeFileName(user) + "-" + sid + ".p12"
			streams = append(streams,
				prefString("certificateLocation0", "cert/"+userFile),
				prefString("clientPassword0", pw))
			app = append(app, prefString("certificateLocation", "cert/"+userFile), prefString("clientPassword", pw))
			entries = append(entries, zipEntry{"certs/" + userFile, p12})
		}
	default:
		return nil, "", fmt.Errorf("unknown package type %q", kind)
	}
	if u, ok := s.dir.User(user); ok {
		if u.Callsign != "" {
			app = append(app, prefString("locationCallsign", u.Callsign))
		}
		if u.Team != "" {
			app = append(app, prefString("locationTeam", u.Team))
		}
		if u.TeamRole != "" {
			app = append(app, prefString("atakRoleType", u.TeamRole))
		}
	}
	pref := prefsXML(map[string][]prefEntry{"cot_streams": streams, "com.atakmap.app_preferences": app}, []string{"cot_streams", "com.atakmap.app_preferences"})
	entries = append([]zipEntry{{"certs/" + prefName, []byte(pref)}}, entries...)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	title := name
	if user != "" {
		title = name + " - " + user
	}
	manifest := manifestXML(cot.NewUID(), title, true, names)
	entries = append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifest)}}, entries...)
	data, err := buildZip(entries)
	if err != nil {
		return nil, "", err
	}
	file := safeFileName(strings.ReplaceAll(name, " ", "-"))
	if user != "" {
		file += "-" + safeFileName(user)
	}
	switch kind {
	case PackageTCP:
		file += "-tcp"
	case PackageEnroll:
		file += "-enroll"
	}
	return data, file + ".zip", nil
}

func (s *Server) buildProfile(r *http.Request, enrollment bool, clientUID string, secago int64) ([]byte, error) {
	cfg := s.Config()
	host := s.hostOf(r)
	trust, err := s.pki.TrustStore()
	if err != nil {
		return nil, err
	}
	folder := "profile-" + s.shortID()
	trustPath := folder + "/truststore-" + s.shortID() + ".p12"
	app := []prefEntry{
		prefBool("prefs_enable_channels", cfg.Channels),
		prefString("prefs_enable_channels_host-"+host, strconv.FormatBool(cfg.Channels)),
		prefBool("deviceProfileEnableOnConnect", true),
		prefBool("repoStartupSync", true),
		prefBool("appMgmtEnableUpdateServer", true),
		prefString("atakUpdateServerUrl", fmt.Sprintf("https://%s:%d/api/packages", HostForURL(host), cfg.Ports.HTTPS)),
		prefString("updateServerCaLocation", "/storage/emulated/0/atak/cert/"+trustPath[len(folder)+1:]),
		prefString("updateServerCaPassword", cfg.Certificates.Password),
	}
	profiles := s.profileEntries(enrollment, clientUID, secago)
	if !enrollment && len(profiles.prefs) == 0 && len(profiles.files) == 0 {
		return nil, nil
	}
	app = append(app, profiles.prefs...)
	pref := prefsXML(map[string][]prefEntry{"com.atakmap.app_preferences": app}, []string{"com.atakmap.app_preferences"})
	entries := []zipEntry{{folder + "/preference.pref", []byte(pref)}, {trustPath, trust}}
	for _, f := range profiles.files {
		entries = append(entries, zipEntry{folder + "/" + f.Name, f.Data})
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	label := "Connection Profile"
	if enrollment {
		label = "Enrollment Profile"
	}
	manifest := manifestXML(cot.NewUID(), cfg.Name+" "+label, true, names)
	return buildZip(append([]zipEntry{{"MANIFEST/manifest.xml", []byte(manifest)}}, entries...))
}

func (s *Server) ATAKEnrollURI(host, user, token string) string {
	return ATAKEnrollLink(s.Config(), host, user, token)
}

func ATAKEnrollLink(cfg Config, host, user, token string) string {
	h := host
	if cfg.Ports.TLS != 8089 && cfg.Ports.TLS > 0 {
		h = HostForURL(host) + ":" + strconv.Itoa(cfg.Ports.TLS)
	}
	q := url.Values{}
	q.Set("host", h)
	q.Set("username", user)
	q.Set("token", token)
	return "tak://com.atakmap.app/enroll?" + q.Encode()
}

func (s *Server) ITAKString(host string, tcp bool) string {
	return ITAKConnectString(s.Config(), host, tcp)
}

func ITAKConnectString(cfg Config, host string, tcp bool) string {
	name := strings.ReplaceAll(cfg.Name, ",", " ")
	if tcp {
		port := cfg.Ports.TCP
		if port == 0 {
			port = cfg.Ports.TCPAlt
		}
		return fmt.Sprintf("%s,%s,%d,TCP", name, host, port)
	}
	return fmt.Sprintf("%s,%s,%d,SSL", name, host, cfg.Ports.TLS)
}

func ImportURI(downloadURL string) string {
	return "tak://com.atakmap.app/import?url=" + url.QueryEscape(downloadURL)
}

func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
