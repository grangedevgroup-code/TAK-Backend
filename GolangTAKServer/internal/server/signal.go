package server

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type SignalPreKey struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type SignalSignedPreKey struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Timestamp int64  `json:"timestamp"`
}

type SignalKyberPreKey struct {
	KeyID      int    `json:"keyId"`
	PublicKey  string `json:"publicKey"`
	Signature  string `json:"signature"`
	Timestamp  int64  `json:"timestamp"`
	LastResort bool   `json:"lastResort"`
}

type SignalBundle struct {
	UID            string              `json:"uid"`
	Username       string              `json:"username"`
	DeviceID       int                 `json:"deviceId"`
	RegistrationID int                 `json:"registrationId"`
	IdentityKey    string              `json:"identityKey"`
	SignedPreKey   *SignalSignedPreKey `json:"signedPreKey"`
	KyberPreKeys   []SignalKyberPreKey `json:"kyberPreKeys"`
	PreKeys        []SignalPreKey      `json:"preKeys"`
	Updated        time.Time           `json:"updated"`
}

type signalStore struct {
	db *store.Collection[SignalBundle]
	mu sync.Mutex
}

func openSignal(dataDir string) (*signalStore, error) {
	db, err := store.Open[SignalBundle](filepath.Join(dataDir, "db", "signal-prekeys.jsonl"), true)
	if err != nil {
		return nil, err
	}
	return &signalStore{db: db}, nil
}

func signalKey(uid string, device int) string { return uid + "\x00" + strconv.Itoa(device) }

func (st *signalStore) bundleFor(uid string) (SignalBundle, bool) {
	var list []SignalBundle
	for _, b := range st.db.All() {
		if b.UID == uid {
			list = append(list, b)
		}
	}
	if len(list) == 0 {
		return SignalBundle{}, false
	}
	sort.Slice(list, func(i, j int) bool { return list[i].DeviceID < list[j].DeviceID })
	return list[0], true
}

func (s *Server) signalPost(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("clientUid")
	var b SignalBundle
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&b); err != nil || uid == "" || b.IdentityKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := identityOf(r)
	b.UID, b.Updated = uid, time.Now().UTC()
	if id != nil && !id.Anon {
		b.Username = id.Name
	}
	s.signal.mu.Lock()
	defer s.signal.mu.Unlock()
	key := signalKey(uid, b.DeviceID)
	if old, ok := s.signal.db.Get(key); ok && old.Username != "" && old.Username != b.Username && (id == nil || !id.Admin) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if b.PreKeys == nil {
		b.PreKeys = []SignalPreKey{}
	}
	if b.KyberPreKeys == nil {
		b.KyberPreKeys = []SignalKyberPreKey{}
	}
	if err := s.signal.db.Put(key, b); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) signalPreKeyCount(w http.ResponseWriter, r *http.Request) {
	b, ok := s.signal.bundleFor(r.URL.Query().Get("clientUid"))
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, len(b.PreKeys))
}

func (s *Server) signalMetadata(w http.ResponseWriter, r *http.Request) {
	b, ok := s.signal.bundleFor(r.URL.Query().Get("clientUid"))
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"uid": b.UID, "deviceId": b.DeviceID, "registrationId": b.RegistrationID, "identityKey": b.IdentityKey, "preKeyCount": len(b.PreKeys), "kyberPreKeyCount": len(b.KyberPreKeys)})
}

func (s *Server) signalNextBundle(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("clientUid")
	s.signal.mu.Lock()
	defer s.signal.mu.Unlock()
	b, ok := s.signal.bundleFor(uid)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	out := b
	out.PreKeys, out.KyberPreKeys = []SignalPreKey{}, []SignalKyberPreKey{}
	if i := slices.IndexFunc(b.KyberPreKeys, func(k SignalKyberPreKey) bool { return !k.LastResort }); i >= 0 {
		out.KyberPreKeys = append(out.KyberPreKeys, b.KyberPreKeys[i])
		b.KyberPreKeys = slices.Delete(slices.Clone(b.KyberPreKeys), i, i+1)
	} else if i := slices.IndexFunc(b.KyberPreKeys, func(k SignalKyberPreKey) bool { return k.LastResort }); i >= 0 {
		out.KyberPreKeys = append(out.KyberPreKeys, b.KyberPreKeys[i])
	}
	if len(b.PreKeys) > 0 {
		out.PreKeys = append(out.PreKeys, b.PreKeys[0])
		b.PreKeys = slices.Clone(b.PreKeys[1:])
	}
	s.signal.db.Put(signalKey(b.UID, b.DeviceID), b)
	writeJSON(w, http.StatusOK, out)
}

type xmppTransfer struct {
	Key     string    `json:"key"`
	Hash    string    `json:"hash"`
	Size    int64     `json:"size"`
	User    string    `json:"user"`
	Created time.Time `json:"created"`
}

type xmppStore struct {
	db    *store.Collection[xmppTransfer]
	blobs *store.Blobs
}

func openXMPP(dataDir string) (*xmppStore, error) {
	db, err := store.Open[xmppTransfer](filepath.Join(dataDir, "db", "xmpp-transfers.jsonl"), true)
	if err != nil {
		return nil, err
	}
	blobs, err := store.OpenBlobs(filepath.Join(dataDir, "xmpp-transfers"))
	if err != nil {
		db.Close()
		return nil, err
	}
	return &xmppStore{db: db, blobs: blobs}, nil
}

func (x *xmppStore) expire(age time.Duration) {
	cut := time.Now().Add(-age)
	for _, t := range x.db.All() {
		if t.Created.Before(cut) {
			x.db.Delete(t.Key)
			inUse := false
			for _, o := range x.db.All() {
				if o.Hash == t.Hash {
					inUse = true
				}
			}
			if !inUse {
				x.blobs.Delete(t.Hash)
			}
		}
	}
}

func (s *Server) xmppPut(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("uid") + "/" + safeFileName(r.PathValue("filename"))
	hash, size, err := s.xmpp.blobs.Put(http.MaxBytesReader(w, r.Body, s.uploadLimit()), s.uploadLimit())
	if err != nil {
		writeText(w, http.StatusBadRequest, err.Error())
		return
	}
	user := ""
	if id := identityOf(r); id != nil {
		user = id.Name
	}
	s.xmpp.db.Put(key, xmppTransfer{Key: key, Hash: hash, Size: size, User: user, Created: time.Now().UTC()})
	s.xmpp.expire(7 * 24 * time.Hour)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) xmppGet(w http.ResponseWriter, r *http.Request) {
	t, ok := s.xmpp.db.Get(r.PathValue("uid") + "/" + safeFileName(r.PathValue("filename")))
	if !ok {
		writeText(w, http.StatusNotFound, "no such file")
		return
	}
	f, err := s.xmpp.blobs.Open(t.Hash)
	if err != nil {
		writeText(w, http.StatusNotFound, "file content missing")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, r.PathValue("filename"), t.Created, f)
}

func (s *Server) signalXMPPRoutes(m func(string, http.HandlerFunc)) {
	m("POST /Marti/api/signal/identity", s.signalPost)
	m("GET /Marti/api/signal/identity", s.signalNextBundle)
	m("GET /Marti/api/signal/identity/preKeyCount", s.signalPreKeyCount)
	m("GET /Marti/api/signal/identity/metadata", s.signalMetadata)
	m("PUT /Marti/api/xmpp/transfer/{uid}/{filename}", s.xmppPut)
	m("GET /Marti/api/xmpp/transfer/{uid}/{filename}", s.xmppGet)
}
