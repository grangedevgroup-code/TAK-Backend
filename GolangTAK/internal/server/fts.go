package server

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/qr"
)

var ftsAttitude = map[string]string{
	"friend": "f", "friendly": "f", "hostile": "h", "unknown": "u", "pending": "p", "assumed": "a",
	"neutral": "n", "suspect": "s", "joker": "j", "faker": "k",
}

var ftsHow = map[string]string{
	"mensurated": "m-i", "human": "h-t", "retyped": "h-t", "machine": "m-", "gps": "m-g", "nonCoT": "h-g-i-g-o",
	"gigo": "h-g-i-g-o", "estimated": "h-e", "calculated": "h-c", "transcribed": "h-t", "pasted": "h-p",
	"magnetic": "m-m", "ins": "m-n", "simulated": "m-s", "configured": "m-c", "radio": "m-r", "passed": "m-p",
	"propagated": "m-p", "fused": "m-f", "tracker": "m-a", "ins+gps": "m-g-n", "dgps": "m-g-d",
}

var ftsTypes = map[string]string{
	"Ground": "a-.-G", "Sniper": "a-.-G-U-C-I-d", "Medic": "a-.-G-U-i-m-etf", "Recon": "a-.-G-U-C-R", "LMG": "a-.-G-E-W-R",
	"Grenadier": "a-.-G-E-W-Z", "anti Tank": "a-.-G-U-C-A-A", "AA": "a-.-G-U-C-D", "Engineer": "a-.-G-U-C-E", "Mortar": "a-.-G-E-W-O",
	"Vehicle": "a-.-G-E-V-C", "Ambulance": "a-.-G-E-V-m", "Emergency Station": "a-.-G-I-i-e", "Police Station": "a-.-G-I-i-l",
	"gas Station": "a-.-G-I-R-P", "Power Station": "a-.-G-I-U-E", "Telco Station": "a-.-G-I-U-T", "Hospital": "a-.-G-I-X-H",
	"Resources": "a-.-G-U-i", "Food": "b-r-.-O-O-O", "Police": "a-.-G-U-i-l-cct", "Incident": "a-.-X-i-o", "SAR": "a-.-A-M-F-Q-H",
	"Medevac": "a-.-G-U-C-V-R-E", "Alarm": "b-l", "Disorder": "b-l-l-l-cd", "Refugees": "b-r-.-O-I-R", "Riot": "b-r-.-O-I-V",
	"Gnd Combat Infantry Rifleman": "a-.-G-U-C-I", "Gnd Combat Infantry grenadier": "a-.-G-E-W-Z", "Gnd Combat Infantry Mortar": "a-.-G-E-W-O",
	"Gnd Combat Infantry MachineGunner (LMG)": "a-.-G-E-W-R", "Gnd Combat Infantry Medic": "a-.-G-U-i-m-etf", "Gnd Combat Infantry Sniper": "a-.-G-U-C-I-d",
	"Gnd Combat Infantry Recon": "a-.-G-U-C-R", "Gnd Combat Infantry anti Tank": "a-.-G-U-C-A-A", "Gnd Combat Infantry air defense": "a-.-G-U-C-D",
	"Gnd Combat Infantry Engineer": "a-.-G-U-C-E", "geo incident": "a-.-X-i-g", "avalanche": "a-.-X-i-g-a", "earthquake": "a-.-X-i-g-e",
	"landslide": "a-.-X-i-g-l", "subsistance": "a-.-X-i-g-s", "volcano": "a-.-X-i-g-v", "eruption": "a-.-X-i-g-v-e", "drought": "a-.-X-i-m-d",
	"cyclone": "a-.-X-i-m-c", "tsunami": "a-.-X-i-m-n", "fire": "a-.-X-i-f", "medical incident": "a-.-X-i-h", "vehicle accident": "a-.-X-i-t-v-a",
	"Air Air Track": "a-.-A", "Air Civ": "a-.-A-C", "Air Civ fixed": "a-.-A-C-F", "Air Civ rotary": "a-.-A-C-H", "Air Mil": "a-.-A-M",
	"Air Mil Fixed": "a-.-A-M-F", "Air Mil Rotary": "a-.-A-M-H", "Sea Surface": "a-.-S", "Subsurface": "a-.-U", "Space": "a-.-P",
}

var ftsEmergency = map[string]string{
	"911 Alert": "b-a-o-tbl", "Ring The Bell": "b-a-o-pan", "Geo-fence Breached": "b-a-g", "In Contact": "b-a-o-opn",
}

type ftsBody map[string]any

func (b ftsBody) str(k string) string {
	switch v := b[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return ""
	default:
		return ""
	}
}

func (b ftsBody) num(k string) (float64, bool) {
	switch v := b[k].(type) {
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}

func readFTS(r *http.Request) (ftsBody, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var b ftsBody
	if len(strings.TrimSpace(string(body))) == 0 {
		return ftsBody{}, nil
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, errors.New("invalid JSON")
	}
	return b, nil
}

func ftsCoTType(kind, attitude string) string {
	t := kind
	if mapped, ok := ftsTypes[kind]; ok {
		t = mapped
	}
	if t == "" {
		t = "a-.-G"
	}
	a := "u"
	if v, ok := ftsAttitude[strings.ToLower(attitude)]; ok {
		a = v
	}
	return strings.Replace(t, ".", a, 1)
}

func destination(lat, lon, meters, bearing float64) (float64, float64) {
	const r = 6371008.8
	d := meters / r
	br := bearing * math.Pi / 180
	la1 := lat * math.Pi / 180
	lo1 := lon * math.Pi / 180
	la2 := math.Asin(math.Sin(la1)*math.Cos(d) + math.Cos(la1)*math.Sin(d)*math.Cos(br))
	lo2 := lo1 + math.Atan2(math.Sin(br)*math.Sin(d)*math.Cos(la1), math.Cos(d)-math.Sin(la1)*math.Sin(la2))
	return la2 * 180 / math.Pi, math.Mod(lo2*180/math.Pi+540, 360) - 180
}

func (s *Server) ftsPublish(r *http.Request, e *cot.Event) *Message {
	id := identityOf(r)
	m := NewMessage(e, s.apiClient(id), id.In)
	m.Everyone = id.Admin
	s.hub.Identify(m.Source, m)
	s.hub.Publish(m)
	return m
}

func (s *Server) ftsTimeout(b ftsBody, def time.Duration) time.Duration {
	if v, ok := b.num("timeout"); ok && v > 0 {
		return time.Duration(v) * time.Second
	}
	return def
}

func (s *Server) ftsGeoObject(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, ok1 := b.num("latitude")
	lon, ok2 := b.num("longitude")
	if !ok1 || !ok2 {
		writeText(w, http.StatusBadRequest, "latitude and longitude are required")
		return
	}
	if dist, ok := b.num("distance"); ok {
		bearing, _ := b.num("bearing")
		if _, has := b["bearing"]; !has {
			bearing = 360
		}
		lat, lon = destination(lat, lon, dist, bearing)
	}
	uid := b.str("uid")
	if uid == "" {
		if r.Method == http.MethodPut {
			writeText(w, http.StatusBadRequest, "uid is a required parameter")
			return
		}
		uid = cot.NewUID()
	}
	how := firstNonEmpty(ftsHow[b.str("how")], "h-g-i-g-o")
	e := cot.New(uid, ftsCoTType(b.str("geoObject"), b.str("attitude")), how, s.ftsTimeout(b, 5*time.Minute))
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(b.str("name"), "Object"))
	if rem := b.str("remarks"); rem != "" {
		e.Detail.AddNew("remarks").Text = rem
	}
	e.Detail.AddNew("archive")
	m := s.ftsPublish(r, e)
	if b.str("repeat") == "true" {
		s.addRepeated(m, identityOf(r).Name)
	}
	writeText(w, http.StatusOK, uid)
}

func (s *Server) ftsGetGeoObjects(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lat, _ := strconv.ParseFloat(q.Get("latitude"), 64)
	lon, _ := strconv.ParseFloat(q.Get("longitude"), 64)
	radius, err := strconv.ParseFloat(q.Get("radius"), 64)
	if err != nil || radius <= 0 {
		radius = 100
	}
	attitude := ftsAttitude[strings.ToLower(q.Get("attitude"))]
	out := []map[string]any{}
	for _, m := range s.hub.Cached() {
		e := m.Event
		if !strings.HasPrefix(e.Type, "a-") {
			continue
		}
		if attitude != "" && (len(e.Type) < 3 || e.Type[2:3] != attitude) {
			continue
		}
		if distanceMeters(lat, lon, e.Point.Lat, e.Point.Lon) > radius {
			continue
		}
		out = append(out, map[string]any{"uid": e.UID, "type": e.Type, "name": e.Callsign(), "latitude": e.Point.Lat, "longitude": e.Point.Lon, "how": e.How, "time": e.Time, "stale": e.Stale})
	}
	writeJSON(w, http.StatusOK, out)
}

func distanceMeters(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371008.8
	p1, p2 := lat1*math.Pi/180, lat2*math.Pi/180
	dp := (lat2 - lat1) * math.Pi / 180
	dl := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dp/2)*math.Sin(dp/2) + math.Cos(p1)*math.Cos(p2)*math.Sin(dl/2)*math.Sin(dl/2)
	return 2 * r * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func (s *Server) ftsChat(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	msg := firstNonEmpty(b.str("message"), b.str("text"), b.str("remarks"))
	if msg == "" {
		if d, ok := b["detail"].(map[string]any); ok {
			if rem, ok := d["remarks"].(map[string]any); ok {
				msg, _ = rem["INTAG"].(string)
			}
		}
	}
	if msg == "" {
		writeText(w, http.StatusBadRequest, "message is required")
		return
	}
	sender := firstNonEmpty(b.str("sender"), s.Config().Name)
	e := cot.Chat(s.UID(), sender, "All Chat Rooms", "All Chat Rooms", msg, nil)
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, "success")
}

func (s *Server) ftsPresence(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, ok1 := b.num("latitude")
	lon, ok2 := b.num("longitude")
	if !ok1 || !ok2 {
		writeText(w, http.StatusBadRequest, "latitude and longitude are required")
		return
	}
	uid := firstNonEmpty(b.str("uid"), cot.NewUID())
	e := cot.New(uid, "a-f-G-U-C", firstNonEmpty(ftsHow[b.str("how")], "h-g-i-g-o"), s.ftsTimeout(b, 5*time.Minute))
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(b.str("name"), "Presence"))
	e.Detail.AddNew("__group", "name", firstNonEmpty(b.str("team"), "Cyan"), "role", firstNonEmpty(b.str("role"), "Team Member"))
	if rem := b.str("remarks"); rem != "" {
		e.Detail.AddNew("remarks").Text = rem
	}
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, uid)
}

func (s *Server) ftsRoute(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, ok1 := b.num("latitude")
	lon, ok2 := b.num("longitude")
	lat2, ok3 := b.num("latitudeDest")
	lon2, ok4 := b.num("longitudeDest")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		writeText(w, http.StatusBadRequest, "latitude, longitude, latitudeDest and longitudeDest are required")
		return
	}
	uid := cot.NewUID()
	e := cot.New(uid, "b-m-r", "h-e", s.ftsTimeout(b, 24*time.Hour))
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("link", "uid", cot.NewUID(), "callsign", firstNonEmpty(b.str("startName"), "Start"), "type", "b-m-p-w", "point", cot.FormatFloat(lat)+","+cot.FormatFloat(lon), "remarks", "", "relation", "c")
	e.Detail.AddNew("link", "uid", cot.NewUID(), "callsign", firstNonEmpty(b.str("endName"), "End"), "type", "b-m-p-w", "point", cot.FormatFloat(lat2)+","+cot.FormatFloat(lon2), "remarks", "", "relation", "c")
	e.Detail.AddNew("link_attr", "color", "-1", "method", firstNonEmpty(b.str("method"), "Driving"), "direction", "Infil", "routetype", "Primary", "order", "Ascending Check Points")
	e.Detail.AddNew("strokeColor", "value", "-1")
	e.Detail.AddNew("strokeWeight", "value", "4.0")
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(b.str("routeName"), "Route"))
	e.Detail.AddNew("remarks")
	e.Detail.AddNew("__routeinfo").AddNew("__navcues")
	e.Detail.AddNew("archive")
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, uid)
}

func (s *Server) ftsEmergencyPost(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, _ := b.num("latitude")
	lon, _ := b.num("longitude")
	name := firstNonEmpty(b.str("name"), s.Config().Name)
	kind := firstNonEmpty(b.str("emergencyType"), "911 Alert")
	typ := firstNonEmpty(ftsEmergency[kind], "b-a-o-tbl")
	uid := firstNonEmpty(b.str("uid"), cot.NewUID()+"-9-1-1")
	e := cot.New(uid, typ, "m-g", 10*time.Minute)
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("link", "uid", s.UID(), "type", "a-f-G-U-C", "relation", "p-p")
	e.Detail.AddNew("contact", "callsign", name)
	e.Detail.AddNew("emergency", "type", kind).Text = name
	if rem := b.str("remarks"); rem != "" {
		e.Detail.AddNew("remarks").Text = rem
	}
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, uid)
}

func (s *Server) ftsEmergencyDelete(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	uid := b.str("uid")
	if uid == "" {
		writeText(w, http.StatusBadRequest, "uid is required")
		return
	}
	e := cot.New(uid, "b-a-o-can", "m-g", time.Minute)
	if m := s.hub.CachedEvent(uid); m != nil {
		e.Point = m.Event.Point
	}
	e.Detail.AddNew("link", "uid", s.UID(), "type", "a-f-G-U-C", "relation", "p-p")
	e.Detail.AddNew("emergency", "cancel", "true").Text = s.Config().Name
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, "success")
}

func (s *Server) ftsEmergencyGet(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{}
	for _, m := range s.hub.Emergencies() {
		e := m.Event
		em := e.D("emergency")
		list = append(list, map[string]any{"uid": e.UID, "lat": e.Point.Lat, "lon": e.Point.Lon, "type": em.Attr("type"), "name": e.Callsign(), "remarks": e.Remarks()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"json_list": list})
}

func (s *Server) ftsDrone(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, ok1 := b.num("latitude")
	lon, ok2 := b.num("longitude")
	if !ok1 || !ok2 {
		writeText(w, http.StatusBadRequest, "latitude and longitude are required")
		return
	}
	uid := firstNonEmpty(b.str("uid"), cot.NewUID())
	e := cot.New(uid, "a-f-A-M-F-Q", "m-g", s.ftsTimeout(b, 5*time.Minute))
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", firstNonEmpty(b.str("name"), "Drone"))
	e.Detail.AddNew("sensor", "fov", firstNonEmpty(b.str("FieldOfView"), "45"), "vfov", "45", "range", firstNonEmpty(b.str("Range"), "100"),
		"azimuth", firstNonEmpty(b.str("Bearing"), "0"), "elevation", "0", "roll", "0", "model", "Drone", "type", "r-e",
		"strokeColor", "-16777216", "fovAlpha", "0.3", "displayMagneticReference", "0", "hideFov", "false")
	if v := b.str("VideoURLUID"); v != "" {
		if f, ok := s.videos.Get(v); ok {
			e.Detail.AddNew("__video", "url", f.URL(), "uid", v)
		}
	}
	s.ftsPublish(r, e)
	spiLat, okA := b.num("SPILatitude")
	spiLon, okB := b.num("SPILongitude")
	if okA && okB {
		spi := s.spiEvent(uid, firstNonEmpty(b.str("SPIName"), "SPI"), spiLat, spiLon, s.ftsTimeout(b, 5*time.Minute))
		s.ftsPublish(r, spi)
		writeJSON(w, http.StatusOK, map[string]string{"uid": uid, "SPI_uid": spi.UID})
		return
	}
	writeText(w, http.StatusOK, uid)
}

func (s *Server) spiEvent(droneUID, name string, lat, lon float64, stale time.Duration) *cot.Event {
	e := cot.New(cot.NewUID(), "b-m-p-s-p-i", "m-g", stale)
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: cot.Unknown, Ce: cot.Unknown, Le: cot.Unknown}
	e.Detail.AddNew("contact", "callsign", name)
	if droneUID != "" {
		e.Detail.AddNew("link", "uid", droneUID, "type", "a-f-A-M-F-Q", "relation", "p-p")
	}
	e.Detail.AddNew("archive")
	return e
}

func (s *Server) ftsSPI(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	lat, ok1 := b.num("latitude")
	lon, ok2 := b.num("longitude")
	if !ok1 || !ok2 {
		writeText(w, http.StatusBadRequest, "latitude and longitude are required")
		return
	}
	e := s.spiEvent(b.str("droneUid"), firstNonEmpty(b.str("name"), "SPI"), lat, lon, s.ftsTimeout(b, 5*time.Minute))
	if uid := b.str("uid"); uid != "" {
		e.UID = uid
	}
	s.ftsPublish(r, e)
	writeText(w, http.StatusOK, e.UID)
}

func (s *Server) ftsVideoGet(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for i, f := range s.videos.All() {
		out[strconv.Itoa(i+1)] = map[string]any{"url": f.Path, "path": f.Path, "port": f.Port, "address": f.Address, "uid": f.UID, "alias": f.Alias}
	}
	writeJSON(w, http.StatusOK, map[string]any{"video_stream": out})
}

func (s *Server) ftsVideoPost(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	addr := b.str("streamAddress")
	if addr == "" {
		writeText(w, http.StatusBadRequest, "streamAddress is required")
		return
	}
	proto := firstNonEmpty(b.str("streamProtocol"), "rtsp")
	if strings.Contains(addr, "://") {
		f := feedFromURL(addr)
		addr, proto = f.Address, firstNonEmpty(f.Protocol, proto)
	}
	port, _ := strconv.Atoi(b.str("streamPort"))
	f := VideoFeed{UID: cot.NewUID(), Alias: firstNonEmpty(b.str("alias"), b.str("streamPath"), addr), Protocol: proto, Address: addr, Port: port,
		Path: b.str("streamPath"), Groups: s.identityGroups(identityOf(r)), Creator: identityOf(r).Name, Active: true}
	for _, old := range s.videos.All() {
		if old.URL() == f.URL() {
			s.ftsPublish(r, s.VideoEvent(old))
			writeText(w, http.StatusCreated, "entry already exists in db "+old.UID+" resending existing entry")
			return
		}
	}
	s.videos.Put(f)
	s.ftsPublish(r, s.VideoEvent(f))
	writeText(w, http.StatusOK, f.UID)
}

func (s *Server) ftsVideoDelete(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	uid := firstNonEmpty(b.str("uid"), b.str("id"))
	for _, f := range s.videos.All() {
		if f.UID == uid || (b.str("streamAddress") != "" && f.Address == b.str("streamAddress") && f.Path == b.str("streamPath")) {
			s.videos.Delete(f.UID)
			s.ftsPublish(r, cot.DeleteFor(f.UID, "b-i-v"))
		}
	}
	writeText(w, http.StatusOK, "success")
}

func (s *Server) ftsClients(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, c := range s.hub.Clients() {
		if c.Relay {
			continue
		}
		info := c.Info()
		out = append(out, map[string]any{"uid": info.UID, "callsign": info.Callsign, "team": info.Team, "role": info.Role, "ip": remoteIP(c.Remote), "lastUpdate": c.LastSeen(), "protocol": c.Kind, "user": c.User()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"Clients": out})
}

func (s *Server) ftsRecent(w http.ResponseWriter, r *http.Request) {
	out := []eventView{}
	for _, m := range s.hub.Cached() {
		out = append(out, viewOf(m, true))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) ftsURL(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	writeJSON(w, http.StatusOK, map[string]any{"COTURL": cfg.Address + ":" + itoa(cfg.Ports.TCP), "SSLCOTURL": cfg.Address + ":" + itoa(cfg.Ports.TLS),
		"DATAPACKAGEURL": "http://" + HostForURL(cfg.Address) + ":" + itoa(cfg.Ports.HTTP), "SSLDATAPACKAGEURL": "https://" + HostForURL(cfg.Address) + ":" + itoa(cfg.Ports.HTTPS),
		"APIURL": "http://" + HostForURL(cfg.Address) + ":" + itoa(cfg.Ports.API)})
}

func (s *Server) ftsStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	st := func(port int) map[string]any { return map[string]any{"status": port > 0, "port": port} }
	writeJSON(w, http.StatusOK, map[string]any{
		"CoTService": st(cfg.Ports.TCP), "SSLCoTService": st(cfg.Ports.TLS), "DataPackageService": st(cfg.Ports.HTTP),
		"SSLDataPackageService": st(cfg.Ports.HTTPS), "FederationServerService": st(cfg.Ports.Federation), "RestAPIService": st(cfg.Ports.API),
	})
}

func (s *Server) ftsAuthenticate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, err := s.dir.CheckPassword(requestIP(r), q.Get("username"), q.Get("password"))
	if err != nil {
		writeText(w, http.StatusForbidden, "invalid credentials")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"uid": id.Name})
}

func (s *Server) ftsDataPackages(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	switch r.Method {
	case http.MethodGet:
		out := []map[string]any{}
		for _, res := range s.res.All() {
			if !res.Package || !s.resourceVisible(id, res) {
				continue
			}
			priv := 0
			if res.Tool == "private" {
				priv = 1
			}
			out = append(out, map[string]any{"PrimaryKey": res.Key, "UID": res.UID, "Name": res.Name, "Hash": res.Hash, "SubmissionUser": res.Submitter,
				"CreatorUid": res.CreatorUID, "SubmissionDateTime": isoTime(res.Submitted), "Size": res.Size, "Privacy": priv, "Keywords": strings.Join(res.Keywords, ",")})
		}
		writeJSON(w, http.StatusOK, map[string]any{"DataPackages": out})
	case http.MethodDelete:
		b, err := readFTS(r)
		if err != nil {
			writeText(w, http.StatusBadRequest, err.Error())
			return
		}
		if list, ok := b["DataPackages"].([]any); ok {
			for _, item := range list {
				if m, ok := item.(map[string]any); ok {
					h, _ := m["hash"].(string)
					h = firstNonEmpty(h, ftsBody(m).str("Hash"))
					if res, ok := s.res.Get(h); ok && s.canEdit(id, res) {
						s.res.Delete(res.UID)
					}
				}
			}
		}
		writeText(w, http.StatusOK, "success")
	case http.MethodPost:
		q := r.URL.Query()
		res, code, err := s.storeUpload(w, r, Resource{Name: q.Get("filename"), Keywords: []string{"missionpackage"}, Tool: "public", CreatorUID: q.Get("creatorUid"),
			Submitter: id.Name, Groups: s.identityGroups(id), UID: cot.NewUID(), Package: true, MIMEType: "application/x-zip-compressed"})
		if err != nil {
			writeText(w, code, err.Error())
			return
		}
		writeText(w, http.StatusOK, res.Hash)
	case http.MethodPut:
		b, err := readFTS(r)
		if err != nil {
			writeText(w, http.StatusBadRequest, err.Error())
			return
		}
		if list, ok := b["DataPackages"].([]any); ok {
			for _, item := range list {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				fb := ftsBody(m)
				for _, res := range s.res.All() {
					if strconv.FormatInt(res.Key, 10) != fb.str("PrimaryKey") || !s.canEdit(id, res) {
						continue
					}
					s.res.Update(res.UID, func(x *Resource) {
						if v := fb.str("Privacy"); v != "" {
							if v == "1" || v == "true" {
								x.Tool = "private"
							} else {
								x.Tool = "public"
							}
						}
						if v := fb.str("Name"); v != "" {
							x.Name = safeFileName(v)
						}
						if v := fb.str("Keywords"); v != "" {
							x.Keywords = splitList(v)
						}
					})
				}
			}
		}
		writeText(w, http.StatusOK, "success")
	}
}

func (s *Server) ftsBroadcastPackage(w http.ResponseWriter, r *http.Request) {
	b, err := readFTS(r)
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	res, ok := s.res.Get(firstNonEmpty(b.str("DataPackageUID"), b.str("hash"), b.str("uid"), r.URL.Query().Get("DataPackageUID")))
	if !ok {
		writeText(w, http.StatusNotFound, "data package not found")
		return
	}
	r.SetPathValue("uid", res.UID)
	s.apiFileShare(w, r)
}

func (s *Server) ftsQR(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("datapackage_id")
	res, ok := s.res.Get(id)
	if !ok {
		writeText(w, http.StatusNotFound, "data package not found")
		return
	}
	cfg := s.Config()
	u := "http://" + HostForURL(cfg.Address) + ":" + itoa(cfg.Ports.HTTP) + "/Marti/sync/content?hash=" + res.UID
	c, err := qr.Encode(ImportURI(u), qr.M)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(c.PNG(8, 4))
}

func (s *Server) ftsSystemUsers(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, u := range s.dir.Users() {
		if u.Name == SelfTestUser {
			continue
		}
		out = append(out, map[string]any{"Name": u.Name, "Group": strings.Join(u.In, ","), "Token": "", "Password": "", "Certs": len(u.Certs) > 0, "Uid": u.Name, "DeviceType": "mobile"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"SystemUsers": out})
}

func (s *Server) ftsMissions(w http.ResponseWriter, r *http.Request) {
	r.SetPathValue("name", "")
	s.apiMissions(w, r)
}

func (s *Server) ftsRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	g := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, s.guard(accessUser, h)) }
	mux.HandleFunc("GET /Alive", func(w http.ResponseWriter, r *http.Request) { writeText(w, http.StatusOK, "API Alive") })
	mux.HandleFunc("GET /AuthenticateUser", s.ftsAuthenticate)
	g("POST /ManageGeoObject/postGeoObject", s.ftsGeoObject)
	g("PUT /ManageGeoObject/putGeoObject", s.ftsGeoObject)
	g("GET /ManageGeoObject/getGeoObject", s.ftsGetGeoObjects)
	g("GET /ManageGeoObject/GetRepeatedMessages", s.ftsRepeatedGet)
	g("DELETE /ManageGeoObject/DeleteRepeatedMessage", s.ftsRepeatedDelete)
	g("POST /ManageChat/postChatToAll", s.ftsChat)
	g("POST /SendGeoChat", s.ftsChat)
	g("POST /ManagePresence/postPresence", s.ftsPresence)
	g("PUT /ManagePresence/putPresence", s.ftsPresence)
	g("POST /ManageRoute/postRoute", s.ftsRoute)
	g("POST /ManageEmergency/postEmergency", s.ftsEmergencyPost)
	g("GET /ManageEmergency/getEmergency", s.ftsEmergencyGet)
	g("DELETE /ManageEmergency/deleteEmergency", s.ftsEmergencyDelete)
	g("POST /Sensor/postDrone", s.ftsDrone)
	g("POST /Sensor/postSPI", s.ftsSPI)
	g("GET /ManageVideoStream/getVideoStream", s.ftsVideoGet)
	g("POST /ManageVideoStream/postVideoStream", s.ftsVideoPost)
	g("DELETE /ManageVideoStream/deleteVideoStream", s.ftsVideoDelete)
	g("GET /Clients", s.ftsClients)
	g("GET /RecentCoT", s.ftsRecent)
	g("GET /URL", s.ftsURL)
	g("GET /checkStatus", s.ftsStatus)
	g("GET /DataPackageTable", s.ftsDataPackages)
	g("POST /DataPackageTable", s.ftsDataPackages)
	g("PUT /DataPackageTable", s.ftsDataPackages)
	g("DELETE /DataPackageTable", s.ftsDataPackages)
	g("POST /BroadcastDataPackage", s.ftsBroadcastPackage)
	g("GET /GenerateQR", s.ftsQR)
	g("GET /MissionTable", s.ftsMissions)
	mux.HandleFunc("GET /ManageSystemUser/getAll", s.guard(accessAdmin, s.ftsSystemUsers))
	ad := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, s.guard(accessAdmin, h)) }
	ad("POST /ManageSystemUser/postSystemUser", s.ftsSystemUserPost)
	ad("PUT /ManageSystemUser/putSystemUser", s.ftsSystemUserPut)
	ad("DELETE /ManageSystemUser/deleteSystemUser", s.ftsSystemUserDelete)
	ad("GET /FederationTable", s.ftsFederationTable)
	ad("POST /FederationTable", s.ftsFederationTable)
	ad("PUT /FederationTable", s.ftsFederationTable)
	ad("DELETE /FederationTable", s.ftsFederationTable)
	g("GET /ExCheckTable", s.ftsExCheckTable)
	g("POST /ExCheckTable", s.ftsExCheckTable)
	g("DELETE /ExCheckTable", s.ftsExCheckTable)
	g("POST /ManageKML/postKML", s.ftsKML)
	g("GET /ManageGeoObject/getGeoObjectByZone", s.ftsGeoByZone)
	mux.HandleFunc("GET /manageAPI/getHelp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"APIs": []string{"/ManageGeoObject/postGeoObject", "/ManageGeoObject/putGeoObject", "/ManageGeoObject/getGeoObject", "/ManageGeoObject/GetRepeatedMessages", "/ManageGeoObject/DeleteRepeatedMessage",
			"/ManageChat/postChatToAll", "/ManagePresence/postPresence", "/ManagePresence/putPresence", "/ManageRoute/postRoute",
			"/ManageEmergency/postEmergency", "/ManageEmergency/getEmergency", "/ManageEmergency/deleteEmergency", "/Sensor/postDrone", "/Sensor/postSPI",
			"/ManageVideoStream/getVideoStream", "/ManageVideoStream/postVideoStream", "/ManageVideoStream/deleteVideoStream", "/Clients", "/RecentCoT", "/URL",
			"/checkStatus", "/DataPackageTable", "/BroadcastDataPackage", "/GenerateQR", "/MissionTable", "/ManageSystemUser/getAll",
			"/ManageSystemUser/postSystemUser", "/ManageSystemUser/putSystemUser", "/ManageSystemUser/deleteSystemUser", "/FederationTable", "/ExCheckTable", "/ManageKML/postKML", "/ManageGeoObject/getGeoObjectByZone"}})
	})
	return mux
}
