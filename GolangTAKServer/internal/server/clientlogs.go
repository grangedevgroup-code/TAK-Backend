package server

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

const maxClientLogs = 5000

type ClientLog struct {
	ID           int64     `json:"id"`
	UID          string    `json:"uid"`
	Callsign     string    `json:"callsign"`
	Platform     string    `json:"platform"`
	MajorVersion string    `json:"majorVersion"`
	MinorVersion string    `json:"minorVersion"`
	Filename     string    `json:"filename"`
	Hash         string    `json:"hash"`
	Size         int64     `json:"size"`
	User         string    `json:"user,omitempty"`
	Time         time.Time `json:"time"`
}

func openClientLogs(dataDir string) (*store.Collection[ClientLog], error) {
	return store.Open[ClientLog](filepath.Join(dataDir, "db", "client-logs.jsonl"), true)
}

func unpackClientLogs(body []byte) map[string][]byte {
	raw := bytes.TrimSpace(body)
	data := raw
	if dec, err := base64.StdEncoding.DecodeString(string(raw)); err == nil && len(dec) > 0 {
		data = dec
	} else if dec, err := base64.URLEncoding.DecodeString(string(raw)); err == nil && len(dec) > 0 {
		data = dec
	}
	out := map[string][]byte{}
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, "MANIFEST/") || f.UncompressedSize64 > 64<<20 {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
			rc.Close()
			if err == nil {
				out[path.Base(f.Name)] = b
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if len(data) > 0 {
		out["log-"+time.Now().UTC().Format("2006-01-02_15-04-05")+".txt"] = data
	}
	return out
}

func (s *Server) clientLogPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.uploadLimit()))
	if err != nil {
		writeText(w, http.StatusBadRequest, "could not read the log upload")
		return
	}
	r.ParseForm()
	q := r.Form
	if q.Get("uid") == "" {
		writeText(w, http.StatusBadRequest, "uid is required")
		return
	}
	files := unpackClientLogs(body)
	if len(files) == 0 {
		writeText(w, http.StatusBadRequest, "the upload contained no logs")
		return
	}
	user := ""
	if id := identityOf(r); id != nil && !id.Anon {
		user = id.Name
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		hash, err := s.res.blobs.PutBytes(files[name])
		if err != nil {
			writeText(w, http.StatusInternalServerError, err.Error())
			return
		}
		l := ClientLog{ID: nextID(s.clientLogs), UID: q.Get("uid"), Callsign: q.Get("callsign"), Platform: q.Get("platform"),
			MajorVersion: q.Get("majorVersion"), MinorVersion: q.Get("minorVersion"), Filename: safeFileName(name), Hash: hash,
			Size: int64(len(files[name])), User: user, Time: time.Now().UTC()}
		if err := s.clientLogs.Put(strconv.FormatInt(l.ID, 10), l); err != nil {
			writeText(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.alertClientLog(l, files[name])
	}
	s.trimClientLogs()
	s.log.Info("client logs received", "uid", q.Get("uid"), "callsign", q.Get("callsign"), "files", len(names))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) alertClientLog(l ClientLog, data []byte) {
	ec := s.Config().Email
	if !ec.Enabled || !ec.LogAlertsEnabled || len(ec.LogAlertsTo) == 0 {
		return
	}
	if len(ec.LogAlertsExtensions) > 0 && !slices.ContainsFunc(ec.LogAlertsExtensions, func(ext string) bool {
		return strings.HasSuffix(strings.ToLower(l.Filename), strings.ToLower("."+strings.TrimPrefix(ext, ".")))
	}) {
		return
	}
	subject := firstNonEmpty(ec.LogAlertsSubject, s.Config().Name+": log from "+firstNonEmpty(l.Callsign, l.UID))
	text := string(data)
	if len(text) > 64<<10 {
		text = text[:64<<10] + "\n..."
	}
	body := "Device: " + l.Callsign + " (" + l.UID + ")\nPlatform: " + l.Platform + " " + l.MajorVersion + " " + l.MinorVersion + "\nFile: " + l.Filename + "\n\n" + text
	go func() {
		for _, to := range ec.LogAlertsTo {
			if err := s.sendMail(to, subject, body); err != nil {
				s.log.Warn("log alert email failed", "to", to, "err", err)
			}
		}
	}()
}

func (s *Server) trimClientLogs() {
	all := s.clientLogs.All()
	if len(all) <= maxClientLogs {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	for _, l := range all[:len(all)-maxClientLogs] {
		s.clientLogs.Delete(strconv.FormatInt(l.ID, 10))
	}
}

func (s *Server) selectClientLogs(r *http.Request) []ClientLog {
	q := r.URL.Query()
	ids := splitList(firstNonEmpty(q.Get("id"), r.PathValue("id")))
	all := s.clientLogs.All()
	sort.Slice(all, func(i, j int) bool { return all[i].ID > all[j].ID })
	var out []ClientLog
	for _, l := range all {
		if len(ids) > 0 && !slices.Contains(ids, "ALL") && !slices.Contains(ids, strconv.FormatInt(l.ID, 10)) {
			continue
		}
		if v := q.Get("uid"); v != "" && l.UID != v {
			continue
		}
		if v := q.Get("callsign"); v != "" && !strings.EqualFold(l.Callsign, v) {
			continue
		}
		if v := q.Get("platform"); v != "" && !strings.EqualFold(l.Platform, v) {
			continue
		}
		out = append(out, l)
	}
	return out
}

func (s *Server) clientLogGet(w http.ResponseWriter, r *http.Request) {
	list := s.selectClientLogs(r)
	ids := firstNonEmpty(r.URL.Query().Get("id"), r.PathValue("id"))
	if ids == "" {
		if list == nil {
			list = []ClientLog{}
		}
		writeJSON(w, http.StatusOK, list)
		return
	}
	if len(list) == 0 {
		writeText(w, http.StatusNotFound, "no such log")
		return
	}
	if len(list) == 1 && ids != "ALL" {
		data, err := s.res.blobs.Read(list[0].Hash)
		if err != nil {
			writeText(w, http.StatusNotFound, "log content missing")
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+list[0].Filename+`"`)
		w.Write(data)
		return
	}
	var entries []zipEntry
	for _, l := range list {
		if data, err := s.res.blobs.Read(l.Hash); err == nil {
			entries = append(entries, zipEntry{strconv.FormatInt(l.ID, 10) + "_" + safeFileName(firstNonEmpty(l.Callsign, l.UID)) + "_" + l.Filename, data})
		}
	}
	data, err := buildZip(entries)
	if err != nil {
		writeText(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="logs_`+time.Now().UTC().Format("2006-01-02_15-04-05")+`.zip"`)
	w.Write(data)
}

func (s *Server) clientLogDelete(w http.ResponseWriter, r *http.Request) {
	list := s.selectClientLogs(r)
	if firstNonEmpty(r.URL.Query().Get("id"), r.PathValue("id")) == "" {
		writeText(w, http.StatusBadRequest, "id is required")
		return
	}
	for _, l := range list {
		s.clientLogs.Delete(strconv.FormatInt(l.ID, 10))
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": len(list)})
}
