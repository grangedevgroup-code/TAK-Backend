package server

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type localWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *localWriter) Header() http.Header { return w.header }

func (w *localWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *localWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(b)
}

func (w *localWriter) Flush() {}

func (s *Server) LocalRequest(method, target string, body []byte) (int, []byte, http.Header) {
	s.localMu.Lock()
	if s.control == "" {
		s.control = NewSecret(32)
	}
	if s.localMux == nil {
		s.localMux = s.routes()
	}
	h, tok := s.localMux, s.control
	s.localMu.Unlock()
	req, err := http.NewRequest(method, "http://127.0.0.1"+target, bytes.NewReader(body))
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error()), http.Header{}
	}
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Authorization", "Bearer "+tok)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	w := &localWriter{header: http.Header{}}
	h.ServeHTTP(w, req)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.status, w.body.Bytes(), w.header
}

func InitialPasswordPath(dataDir string) string { return filepath.Join(dataDir, "admin-password.txt") }

func (s *Server) EnsureAdmin(password string) (string, string, bool, error) {
	for _, u := range s.dir.Users() {
		if u.Admin && !u.Disabled && !isSelfTest(u.Name) {
			return u.Name, "", false, nil
		}
	}
	name := "admin"
	if password == "" {
		password = FriendlySecret()
	}
	if _, ok := s.dir.User(name); ok {
		if err := s.dir.SetPassword(name, password); err != nil {
			return "", "", false, err
		}
		if _, err := s.dir.UpdateUser(name, func(u *User) error {
			u.Admin, u.Disabled = true, false
			return nil
		}); err != nil {
			return "", "", false, err
		}
	} else if _, err := s.dir.AddUser(name, password, true, nil); err != nil {
		return "", "", false, err
	}
	content := "username: " + name + "\npassword: " + password + "\n"
	if err := writeFileAtomic(InitialPasswordPath(s.DataDir), []byte(content), 0o600); err != nil {
		return "", "", false, err
	}
	s.log.Info("administrator account created", "user", name, "passwordFile", InitialPasswordPath(s.DataDir))
	return name, password, true, nil
}

func ReadInitialPassword(dataDir string) (string, string, error) {
	b, err := os.ReadFile(InitialPasswordPath(dataDir))
	if err != nil {
		return "", "", err
	}
	var user, pw string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "username":
			user = strings.TrimSpace(v)
		case "password":
			pw = strings.TrimSpace(v)
		}
	}
	if user == "" || pw == "" {
		return "", "", errors.New("initial password file is incomplete")
	}
	return user, pw, nil
}

func (s *Server) forgetInitialPassword(name string) {
	if user, _, err := ReadInitialPassword(s.DataDir); err == nil && strings.EqualFold(user, name) {
		os.Remove(InitialPasswordPath(s.DataDir))
	}
}
