package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/xmltree"
)

type MapLayer struct {
	UID                  string   `json:"uid"`
	CreatorUID           string   `json:"creatorUid,omitempty"`
	Name                 string   `json:"name"`
	Description          string   `json:"description,omitempty"`
	Type                 string   `json:"type"`
	URL                  string   `json:"url"`
	TileType             string   `json:"tileType,omitempty"`
	ServerParts          string   `json:"serverParts,omitempty"`
	BackgroundColor      string   `json:"backgroundColor,omitempty"`
	TileUpdate           string   `json:"tileUpdate,omitempty"`
	AdditionalParameters string   `json:"additionalParameters,omitempty"`
	CoordinateSystem     string   `json:"coordinateSystem,omitempty"`
	Version              string   `json:"version,omitempty"`
	Layers               string   `json:"layers,omitempty"`
	Path                 string   `json:"path,omitempty"`
	After                string   `json:"after,omitempty"`
	MinZoom              *int     `json:"minZoom,omitempty"`
	MaxZoom              *int     `json:"maxZoom,omitempty"`
	North                *float64 `json:"north,omitempty"`
	South                *float64 `json:"south,omitempty"`
	East                 *float64 `json:"east,omitempty"`
	West                 *float64 `json:"west,omitempty"`
	Opacity              *int     `json:"opacity,omitempty"`
	CreateTime           string   `json:"createTime,omitempty"`
	ModifiedTime         string   `json:"modifiedTime,omitempty"`
	DefaultLayer         bool     `json:"defaultLayer"`
	Enabled              bool     `json:"enabled"`
	IgnoreErrors         bool     `json:"ignoreErrors"`
	InvertYCoordinate    bool     `json:"invertYCoordinate"`
}

type MapLayers struct {
	db *store.Collection[MapLayer]
}

func OpenMapLayers(dataDir string) (*MapLayers, error) {
	db, err := store.Open[MapLayer](filepath.Join(dataDir, "db", "maplayers.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &MapLayers{db: db}, nil
}

func (ml *MapLayers) Close() { ml.db.Close() }

func (ml *MapLayers) All() []MapLayer {
	all := ml.db.All()
	sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	return all
}

func readMapLayer(r *http.Request) (MapLayer, error) {
	var l MapLayer
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&l); err != nil {
		return l, err
	}
	return l, nil
}

func validMapLayer(l *MapLayer) string {
	l.Name = strings.TrimSpace(l.Name)
	l.URL = strings.TrimSpace(l.URL)
	if l.Name == "" || len(l.Name) > 255 {
		return "a map layer needs a name"
	}
	u, err := url.Parse(l.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "a map layer needs an http or https url"
	}
	if l.Type == "" {
		l.Type = "MapTile"
	}
	if l.Type != "MapTile" && l.Type != "WMS" && l.Type != "WMTS" && l.Type != "XYZ" {
		return "type must be MapTile, WMS, WMTS or XYZ"
	}
	return ""
}

func (s *Server) martiMapLayersAll(w http.ResponseWriter, r *http.Request) {
	out := s.mapLayers.All()
	if out == nil {
		out = []MapLayer{}
	}
	writeJSON(w, http.StatusOK, s.envelope("com.bbn.marti.maplayer.model.MapLayer", out))
}

func (s *Server) martiMapLayerGet(w http.ResponseWriter, r *http.Request) {
	l, ok := s.mapLayers.db.Get(r.PathValue("uid"))
	if !ok {
		writeJSON(w, http.StatusNotFound, s.envelope("MapLayer", nil))
		return
	}
	writeJSON(w, http.StatusOK, s.envelope("MapLayer", l))
}

func (s *Server) martiMapLayerSave(w http.ResponseWriter, r *http.Request) {
	if !identityOf(r).Admin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only administrators can change map layers"})
		return
	}
	l, err := readMapLayer(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a MapLayer in JSON"})
		return
	}
	if msg := validMapLayer(&l); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	now := isoTime(time.Now())
	if r.Method == http.MethodPut {
		old, ok := s.mapLayers.db.Get(l.UID)
		if l.UID == "" || !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no map layer with that uid"})
			return
		}
		l.CreateTime = old.CreateTime
		l.CreatorUID = firstNonEmpty(l.CreatorUID, old.CreatorUID)
	} else {
		if l.UID == "" {
			l.UID = cot.NewUID()
		}
		if _, exists := s.mapLayers.db.Get(l.UID); exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a map layer with that uid already exists"})
			return
		}
		l.CreateTime = now
	}
	l.ModifiedTime = now
	if l.DefaultLayer {
		for _, other := range s.mapLayers.db.All() {
			if other.UID != l.UID && other.DefaultLayer {
				other.DefaultLayer = false
				s.mapLayers.db.Put(other.UID, other)
			}
		}
	}
	if err := s.mapLayers.db.Put(l.UID, l); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("map layer saved", "name", l.Name, "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, s.envelope("MapLayer", l))
}

func (s *Server) martiMapLayerDelete(w http.ResponseWriter, r *http.Request) {
	if !identityOf(r).Admin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only administrators can change map layers"})
		return
	}
	uid := r.PathValue("uid")
	if _, ok := s.mapLayers.db.Get(uid); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no map layer with that uid"})
		return
	}
	s.mapLayers.db.Delete(uid)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) missionMapLayerSave(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMissionAny(w, r)
	if !ok || !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	l, err := readMapLayer(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a MapLayer in JSON"})
		return
	}
	if msg := validMapLayer(&l); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	creator := firstNonEmpty(r.URL.Query().Get("creatorUid"), s.callerUID(r))
	update := r.Method == http.MethodPut
	if !update && l.UID == "" {
		l.UID = cot.NewUID()
	}
	l.CreatorUID = firstNonEmpty(l.CreatorUID, creator)
	m, l, ok = s.putMissionMapLayer(m.Name, l, creator, update)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no map layer with that uid in the mission"})
		return
	}
	kind := "ADD_MAPLAYER_TO_MISSION"
	if update {
		kind = "UPDATE_MAPLAYER"
	}
	s.rolMissionMapLayer(m, l, creator, kind)
	writeJSON(w, http.StatusOK, s.envelope("MapLayer", l))
}

func (s *Server) putMissionMapLayer(name string, l MapLayer, creator string, update bool) (Mission, MapLayer, bool) {
	now := isoTime(time.Now())
	found := false
	m, err := s.missions.Update(name, func(x *Mission) error {
		idx := slices.IndexFunc(x.MapLayers, func(o MapLayer) bool { return o.UID == l.UID })
		if update && idx < 0 {
			return nil
		}
		l.ModifiedTime = now
		if idx >= 0 {
			l.CreateTime = x.MapLayers[idx].CreateTime
			x.MapLayers[idx] = l
		} else {
			l.CreateTime = now
			x.MapLayers = append(x.MapLayers, l)
		}
		lc := l
		x.addChange(MissionChange{Type: "ADD_CONTENT", CreatorUID: creator, ContentUID: l.UID, MapLayer: &lc})
		found = true
		return nil
	})
	if err != nil || !found {
		return m, l, false
	}
	s.notifyMapLayerChange(m, "ADD_CONTENT", creator, l)
	return m, l, true
}

func (s *Server) removeMissionMapLayer(name, uid, creator string) (Mission, MapLayer, bool) {
	var removed MapLayer
	found := false
	m, err := s.missions.Update(name, func(x *Mission) error {
		idx := slices.IndexFunc(x.MapLayers, func(o MapLayer) bool { return o.UID == uid })
		if idx < 0 {
			return nil
		}
		removed = x.MapLayers[idx]
		x.MapLayers = slices.Delete(x.MapLayers, idx, idx+1)
		lc := removed
		x.addChange(MissionChange{Type: "REMOVE_CONTENT", CreatorUID: creator, ContentUID: uid, MapLayer: &lc})
		found = true
		return nil
	})
	if err != nil || !found {
		return m, removed, false
	}
	s.notifyMapLayerChange(m, "REMOVE_CONTENT", creator, removed)
	return m, removed, true
}

func (s *Server) missionMapLayerDelete(w http.ResponseWriter, r *http.Request) {
	m, ok := s.loadMissionAny(w, r)
	if !ok || !s.requirePermission(w, r, m, "MISSION_WRITE") {
		return
	}
	creator := firstNonEmpty(r.URL.Query().Get("creatorUid"), s.callerUID(r))
	m, removed, found := s.removeMissionMapLayer(m.Name, r.PathValue("uid"), creator)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no map layer with that uid in the mission"})
		return
	}
	s.rolMissionMapLayer(m, removed, creator, "REMOVE_MAPLAYER_FROM_MISSION")
	w.WriteHeader(http.StatusOK)
}

func mapLayerXML(l MapLayer) *xmltree.Node {
	n := xmltree.New("mapLayer")
	add := func(k, v string) {
		if v != "" {
			n.AddNew(k).Text = v
		}
	}
	add("uid", l.UID)
	add("creatorUid", l.CreatorUID)
	add("name", l.Name)
	add("description", l.Description)
	add("type", l.Type)
	add("url", l.URL)
	add("tileType", l.TileType)
	add("serverParts", l.ServerParts)
	add("backgroundColor", l.BackgroundColor)
	add("tileUpdate", l.TileUpdate)
	add("additionalParameters", l.AdditionalParameters)
	add("coordinateSystem", l.CoordinateSystem)
	add("version", l.Version)
	add("layers", l.Layers)
	add("createTime", l.CreateTime)
	add("modifiedTime", l.ModifiedTime)
	return n
}

func (s *Server) notifyMapLayerChange(m Mission, typ, author string, l MapLayer) {
	e := s.missionEvent(m, "t-x-m-c", "CHANGE", author)
	mc := s.changeXML(m, typ, author, nil, nil)
	mc.Add(mapLayerXML(l))
	mc.AddNew("contentUid").Text = l.UID
	e.Detail.Child("mission").AddNew("MissionChanges").Add(mc)
	s.sendToSubscribers(m, e, "")
}
