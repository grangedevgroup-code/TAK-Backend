package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

type PluginSetting struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Default  string   `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"`
	Help     string   `json:"help,omitempty"`
	Required bool     `json:"required,omitempty"`
}

type PluginManifest struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author,omitempty"`
	Homepage    string            `json:"homepage,omitempty"`
	Command     string            `json:"command"`
	Commands    map[string]string `json:"commands,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Admin       bool              `json:"admin,omitempty"`
	Groups      []string          `json:"groups,omitempty"`
	HTTP        bool              `json:"http,omitempty"`
	Page        string            `json:"page,omitempty"`
	AdminOnly   bool              `json:"adminOnly,omitempty"`
	Public      bool              `json:"public,omitempty"`
	Settings    []PluginSetting   `json:"settings,omitempty"`
}

const secretMask = "********"

func (m *PluginManifest) CommandFor(goos string) string {
	if c := m.Commands[goos]; c != "" {
		return c
	}
	if c := m.Commands[goos+"/"+runtime.GOARCH]; c != "" {
		return c
	}
	return m.Command
}

func ReadPluginManifest(dir string) (*PluginManifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "plugin.json"))
	if err != nil {
		return nil, err
	}
	var m PluginManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("plugin.json: %w", err)
	}
	for _, st := range m.Settings {
		if st.Key == "" || strings.ContainsAny(st.Key, "=\x00") {
			return nil, errors.New("plugin.json: every setting needs a key")
		}
		switch st.Type {
		case "", "text", "number", "bool", "secret", "select", "textarea":
		default:
			return nil, fmt.Errorf("plugin.json: setting %s has unknown type %q", st.Key, st.Type)
		}
	}
	return &m, nil
}

func (s *Server) pluginWorkDir(p PluginConfig) string {
	dir := s.pluginDir(p.Name)
	if p.Dir != "" {
		if filepath.IsAbs(p.Dir) {
			return p.Dir
		}
		return filepath.Join(dir, p.Dir)
	}
	return dir
}

func (s *Server) pluginManifest(p PluginConfig) *PluginManifest {
	m, err := ReadPluginManifest(s.pluginWorkDir(p))
	if err != nil {
		return nil
	}
	return m
}

func (s *Server) pluginSettingValues(p PluginConfig, m *PluginManifest) map[string]string {
	out := map[string]string{}
	if m != nil {
		for _, st := range m.Settings {
			if st.Default != "" {
				out[st.Key] = st.Default
			}
		}
	}
	for k, v := range p.Settings {
		out[k] = v
	}
	return out
}

func freeLocalAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr, nil
}

func (s *Server) pluginExtraEnv(p PluginConfig, pr *pluginProc) []string {
	m := s.pluginManifest(p)
	settings, _ := json.Marshal(s.pluginSettingValues(p, m))
	env := []string{"GOLANGTAK_PLUGIN_SETTINGS=" + string(settings)}
	if m != nil && m.HTTP {
		if addr, err := freeLocalAddr(); err == nil {
			env = append(env, "GOLANGTAK_PLUGIN_HTTP="+addr)
			pr.set(func() { pr.httpAddr = addr })
		}
	}
	return env
}

func (s *Server) apiServerPluginSettings(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	var cfg *PluginConfig
	for _, p := range s.Config().Plugins {
		if strings.EqualFold(p.Name, name) {
			cp := p
			cfg = &cp
		}
	}
	if cfg == nil {
		apiError(w, http.StatusNotFound, fmt.Errorf("no server plugin named %s", name))
		return
	}
	m := s.pluginManifest(*cfg)
	next := map[string]string{}
	for k, v := range cfg.Settings {
		next[k] = v
	}
	for k, v := range body {
		if len(v) > 8192 {
			apiError(w, http.StatusBadRequest, fmt.Errorf("setting %s is too long", k))
			return
		}
		var def *PluginSetting
		if m != nil {
			for i := range m.Settings {
				if m.Settings[i].Key == k {
					def = &m.Settings[i]
				}
			}
			if def == nil {
				apiError(w, http.StatusBadRequest, fmt.Errorf("the plugin has no setting %s", k))
				return
			}
		}
		if def != nil {
			if def.Type == "secret" && v == secretMask {
				continue
			}
			switch def.Type {
			case "number":
				if _, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err != nil && v != "" {
					apiError(w, http.StatusBadRequest, fmt.Errorf("%s must be a number", def.Label))
					return
				}
			case "bool":
				if v != "true" && v != "false" {
					apiError(w, http.StatusBadRequest, fmt.Errorf("%s must be true or false", def.Label))
					return
				}
			case "select":
				if v != "" && !slices.Contains(def.Options, v) {
					apiError(w, http.StatusBadRequest, fmt.Errorf("%s must be one of %s", def.Label, strings.Join(def.Options, ", ")))
					return
				}
			}
			if def.Required && strings.TrimSpace(v) == "" {
				apiError(w, http.StatusBadRequest, fmt.Errorf("%s is required", firstNonEmpty(def.Label, def.Key)))
				return
			}
		}
		next[k] = v
	}
	if _, err := s.UpdateConfig(func(c *Config) error {
		for i := range c.Plugins {
			if strings.EqualFold(c.Plugins[i].Name, name) {
				c.Plugins[i].Settings = next
			}
		}
		return nil
	}); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	s.reloadPlugins()
	s.log.Info("server plugin settings changed", "plugin", name, "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) pluginProxy(w http.ResponseWriter, r *http.Request) {
	name, rest := r.PathValue("name"), r.PathValue("rest")
	var cfg *PluginConfig
	for _, p := range s.Config().Plugins {
		if strings.EqualFold(p.Name, name) && p.Enabled {
			cp := p
			cfg = &cp
		}
	}
	if cfg == nil || s.plugins == nil {
		http.NotFound(w, r)
		return
	}
	m := s.pluginManifest(*cfg)
	if m == nil || !m.HTTP {
		http.NotFound(w, r)
		return
	}
	addr := s.plugins.httpAddr(cfg.Name)
	if addr == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the plugin is not running"})
		return
	}
	serve := func(w http.ResponseWriter, r *http.Request) {
		target := &url.URL{Scheme: "http", Host: addr}
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.URL.Path = "/" + rest
				pr.Out.URL.RawPath = ""
				pr.Out.Header.Del("Cookie")
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Del("X-CSRF-Token")
				for _, h := range []string{"X-GolangTAK-User", "X-GolangTAK-Admin", "X-GolangTAK-Groups"} {
					pr.Out.Header.Del(h)
				}
				pr.Out.Header.Set("X-GolangTAK-Base", "/plugins/"+url.PathEscape(cfg.Name)+"/")
				if id := identityOf(r); id != nil && !id.Anon {
					pr.Out.Header.Set("X-GolangTAK-User", id.Name)
					pr.Out.Header.Set("X-GolangTAK-Admin", strconv.FormatBool(id.Admin))
					pr.Out.Header.Set("X-GolangTAK-Groups", strings.Join(s.identityGroups(id), ","))
				}
				pr.SetXForwarded()
			},
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Del("Set-Cookie")
				if resp.Header.Get("X-Frame-Options") == "" {
					resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
				}
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the plugin did not answer"})
			},
			FlushInterval: 100 * time.Millisecond,
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.Config().Limits.MaxUploadMB)<<20)
		rp.ServeHTTP(w, r)
	}
	if m.Public && (rest == "public" || strings.HasPrefix(rest, "public/")) {
		serve(w, r)
		return
	}
	level := accessUser
	if m.AdminOnly {
		level = accessAdmin
	}
	s.guard(level, serve)(w, r)
}

func (s *Server) apiPluginPages(w http.ResponseWriter, r *http.Request) {
	id := identityOf(r)
	out := []map[string]string{}
	for _, p := range s.Config().Plugins {
		if !p.Enabled {
			continue
		}
		m := s.pluginManifest(p)
		if m == nil || !m.HTTP || (m.AdminOnly && !id.Admin) {
			continue
		}
		out = append(out, map[string]string{"name": p.Name, "page": firstNonEmpty(m.Page, p.Name), "url": "/plugins/" + url.PathEscape(p.Name) + "/", "description": m.Description})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *pluginManager) httpAddr(name string) string {
	m.mu.Lock()
	pr, ok := m.procs[strings.ToLower(name)]
	m.mu.Unlock()
	if !ok {
		return ""
	}
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if pr.state != "running" {
		return ""
	}
	return pr.httpAddr
}
