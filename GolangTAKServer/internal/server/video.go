package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

type VideoFeed struct {
	UID            string    `json:"uid"`
	Alias          string    `json:"alias"`
	Protocol       string    `json:"protocol"`
	Address        string    `json:"address"`
	Port           int       `json:"port"`
	Path           string    `json:"path"`
	RoverPort      string    `json:"roverPort"`
	IgnoreKLV      bool      `json:"ignoreEmbeddedKLV"`
	PreferredMAC   string    `json:"preferredMacAddress"`
	PreferredIface string    `json:"preferredInterfaceAddress"`
	Buffer         string    `json:"buffer"`
	Timeout        string    `json:"timeout"`
	RTSPReliable   string    `json:"rtspReliable"`
	Classification string    `json:"classification"`
	Thumbnail      string    `json:"thumbnail"`
	Lat            string    `json:"latitude"`
	Lon            string    `json:"longitude"`
	FOV            string    `json:"fov"`
	Heading        string    `json:"heading"`
	Range          string    `json:"range"`
	Groups         []string  `json:"groups"`
	Creator        string    `json:"creator"`
	Updated        time.Time `json:"updated"`
	Active         bool      `json:"active"`
}

func defaultPort(proto string) int {
	switch strings.ToLower(proto) {
	case "rtsp", "rtsps":
		return 554
	case "rtmp":
		return 1935
	case "rtmps":
		return 443
	case "srt":
		return 8890
	case "http", "hls":
		return 80
	case "https":
		return 443
	case "udp", "rtp":
		return 1234
	}
	return 0
}

func (v VideoFeed) URL() string {
	proto := firstNonEmpty(strings.ToLower(v.Protocol), "rtsp")
	host := v.Address
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		return host
	}
	u := proto + "://" + HostForURL(host)
	if v.Port > 0 && v.Port != defaultPort(proto) {
		u += ":" + strconv.Itoa(v.Port)
	}
	p := v.Path
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return u + p
}

func feedFromURL(raw string) VideoFeed {
	var v VideoFeed
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		v.Address = raw
		return v
	}
	v.Protocol = u.Scheme
	v.Address = u.Hostname()
	if u.User != nil {
		v.Address = u.User.String() + "@" + u.Hostname()
	}
	v.Port, _ = strconv.Atoi(u.Port())
	if v.Port == 0 {
		v.Port = defaultPort(u.Scheme)
	}
	v.Path = u.EscapedPath()
	if u.RawQuery != "" {
		v.Path += "?" + u.RawQuery
	}
	return v
}

type Videos struct {
	db *store.Collection[VideoFeed]
}

func OpenVideos(dataDir string) (*Videos, error) {
	db, err := store.Open[VideoFeed](filepath.Join(dataDir, "db", "video.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &Videos{db: db}, nil
}

func (v *Videos) Close() { v.db.Close() }

func (v *Videos) All() []VideoFeed { return v.db.All() }

func (v *Videos) Put(f VideoFeed) error {
	if f.UID == "" {
		f.UID = cot.NewUID()
	}
	f.Updated = time.Now().UTC()
	return v.db.Put(f.UID, f)
}

func (v *Videos) Delete(uid string) error { return v.db.Delete(uid) }

func (v *Videos) Get(uid string) (VideoFeed, bool) { return v.db.Get(uid) }

func (s *Server) videoVisible(id *Identity, f VideoFeed) bool {
	if id == nil {
		return false
	}
	if id.Admin || len(f.Groups) == 0 {
		return true
	}
	return s.visibleTo(id, s.dir.Mask(f.Groups))
}

func feedXML(f VideoFeed) *xmltree.Node {
	n := xmltree.New("feed")
	add := func(k, v string) { n.AddNew(k).Text = v }
	add("protocol", firstNonEmpty(f.Protocol, "rtsp"))
	add("alias", firstNonEmpty(f.Alias, f.UID))
	add("uid", f.UID)
	add("address", f.Address)
	add("port", strconv.Itoa(f.Port))
	add("roverPort", firstNonEmpty(f.RoverPort, "-1"))
	add("ignoreEmbeddedKLV", strconv.FormatBool(f.IgnoreKLV))
	add("preferredMacAddress", f.PreferredMAC)
	add("preferredInterfaceAddress", f.PreferredIface)
	add("path", f.Path)
	add("buffer", f.Buffer)
	add("timeout", firstNonEmpty(f.Timeout, "10000"))
	add("rtspReliable", firstNonEmpty(f.RTSPReliable, "1"))
	return n
}

func (s *Server) vcmGet(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	root := xmltree.New("videoConnections")
	for _, f := range s.videos.All() {
		if s.videoVisible(id, f) {
			root.Add(feedXML(f))
		}
	}
	writeXML(w, http.StatusOK, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+root.String())
}

func (s *Server) vcmPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeText(w, http.StatusBadRequest, "could not read body")
		return
	}
	root, err := xmltree.Parse(body)
	if err != nil {
		writeText(w, http.StatusBadRequest, "invalid XML")
		return
	}
	feeds := root.All("feed")
	if root.Name == "feed" {
		feeds = []*xmltree.Node{root}
	}
	if len(feeds) == 0 {
		feeds = []*xmltree.Node{root}
	}
	id := identityOf(r)
	for _, fn := range feeds {
		get := func(k string) string {
			if c := fn.Child(k); c != nil {
				return strings.TrimSpace(c.Text)
			}
			return ""
		}
		f := VideoFeed{
			UID: get("uid"), Alias: get("alias"), Protocol: get("protocol"), Address: get("address"), Path: get("path"),
			RoverPort: get("roverPort"), IgnoreKLV: strings.EqualFold(get("ignoreEmbeddedKLV"), "true"),
			PreferredMAC: get("preferredMacAddress"), PreferredIface: get("preferredInterfaceAddress"),
			Buffer: get("buffer"), Timeout: get("timeout"), RTSPReliable: get("rtspReliable"),
			Groups: s.identityGroups(id), Creator: id.Name, Active: true,
		}
		f.Port, _ = strconv.Atoi(get("port"))
		if f.Address == "" && f.Path == "" {
			continue
		}
		if f.UID == "" {
			for _, old := range s.videos.All() {
				if old.Alias == f.Alias && f.Alias != "" {
					f.UID = old.UID
				}
			}
		}
		s.videos.Put(f)
		s.log.Info("video feed saved", "alias", f.Alias, "by", id.Name)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) videoJSON(f VideoFeed) map[string]any {
	feed := map[string]any{
		"uuid": f.UID, "active": true, "alias": firstNonEmpty(f.Alias, f.UID), "url": f.URL(), "order": 0,
		"macAddress": f.PreferredMAC, "roverPort": firstNonEmpty(f.RoverPort, "-1"), "ignoreEmbeddedKLV": strconv.FormatBool(f.IgnoreKLV),
		"source": f.URL(), "networkTimeout": firstNonEmpty(f.Timeout, "10000"), "bufferTime": f.Buffer, "rtspReliable": firstNonEmpty(f.RTSPReliable, "1"),
		"thumbnail": f.Thumbnail, "classification": f.Classification, "latitude": f.Lat, "longitude": f.Lon,
		"fov": f.FOV, "heading": f.Heading, "range": f.Range, "width": 0, "height": 0, "bitrate": 0,
	}
	return map[string]any{"uuid": f.UID, "active": true, "alias": firstNonEmpty(f.Alias, f.UID), "thumbnail": f.Thumbnail, "classification": f.Classification, "feeds": []any{feed}}
}

func (s *Server) videoList(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	list := []map[string]any{}
	for _, f := range s.videos.All() {
		if s.videoVisible(id, f) {
			list = append(list, s.videoJSON(f))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"videoConnections": list})
}

func (s *Server) videoGet(w http.ResponseWriter, r *http.Request) {
	f, ok := s.videos.Get(r.PathValue("uid"))
	if !ok || !s.videoVisible(identityOf(r), f) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "video not found"})
		return
	}
	writeJSON(w, http.StatusOK, s.videoJSON(f))
}

func (s *Server) videoPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		VideoConnections []struct {
			UUID           string `json:"uuid"`
			Alias          string `json:"alias"`
			Classification string `json:"classification"`
			Thumbnail      string `json:"thumbnail"`
			Feeds          []struct {
				UUID           string `json:"uuid"`
				Alias          string `json:"alias"`
				URL            string `json:"url"`
				MacAddress     string `json:"macAddress"`
				RoverPort      string `json:"roverPort"`
				IgnoreKLV      string `json:"ignoreEmbeddedKLV"`
				NetworkTimeout string `json:"networkTimeout"`
				BufferTime     string `json:"bufferTime"`
				RTSPReliable   string `json:"rtspReliable"`
				Latitude       string `json:"latitude"`
				Longitude      string `json:"longitude"`
				FOV            string `json:"fov"`
				Heading        string `json:"heading"`
				Range          string `json:"range"`
			} `json:"feeds"`
		} `json:"videoConnections"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	id := identityOf(r)
	for _, vc := range body.VideoConnections {
		for _, fd := range vc.Feeds {
			f := feedFromURL(fd.URL)
			f.UID = firstNonEmpty(vc.UUID, fd.UUID, cot.NewUID())
			f.Alias = firstNonEmpty(fd.Alias, vc.Alias)
			f.Classification, f.Thumbnail = vc.Classification, vc.Thumbnail
			f.PreferredMAC, f.RoverPort = fd.MacAddress, fd.RoverPort
			f.IgnoreKLV = strings.EqualFold(fd.IgnoreKLV, "true")
			f.Timeout, f.Buffer, f.RTSPReliable = fd.NetworkTimeout, fd.BufferTime, fd.RTSPReliable
			f.Lat, f.Lon, f.FOV, f.Heading, f.Range = fd.Latitude, fd.Longitude, fd.FOV, fd.Heading, fd.Range
			f.Groups, f.Creator, f.Active = s.identityGroups(id), id.Name, true
			s.videos.Put(f)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) videoDelete(w http.ResponseWriter, r *http.Request) {
	f, ok := s.videos.Get(r.PathValue("uid"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "video not found"})
		return
	}
	id := identityOf(r)
	if !id.Admin && f.Creator != id.Name {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the creator or an administrator can delete this feed"})
		return
	}
	s.videos.Delete(f.UID)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) VideoEvent(f VideoFeed) *cot.Event {
	e := cot.New(f.UID, "b-i-v", "m-g", 24*time.Hour)
	if lat, err := strconv.ParseFloat(f.Lat, 64); err == nil {
		e.Point.Lat = lat
	}
	if lon, err := strconv.ParseFloat(f.Lon, 64); err == nil {
		e.Point.Lon = lon
	}
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(f.Alias, f.UID))
	e.Detail.AddNew("__video", "url", f.URL()).Add(xmltree.New("ConnectionEntry",
		"networkTimeout", firstNonEmpty(f.Timeout, "12000"), "uid", f.UID, "path", f.Path, "protocol", firstNonEmpty(f.Protocol, "rtsp"),
		"bufferTime", firstNonEmpty(f.Buffer, "-1"), "address", f.Address, "port", strconv.Itoa(f.Port),
		"roverPort", firstNonEmpty(f.RoverPort, "-1"), "rtspReliable", firstNonEmpty(f.RTSPReliable, "0"),
		"ignoreEmbeddedKLV", strconv.FormatBool(f.IgnoreKLV), "alias", firstNonEmpty(f.Alias, f.UID)))
	return e
}
