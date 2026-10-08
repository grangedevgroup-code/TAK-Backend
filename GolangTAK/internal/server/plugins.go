package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PluginConfig struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Dir     string            `json:"dir,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Enabled bool              `json:"enabled"`
	Admin   bool              `json:"admin,omitempty"`
	Groups  []string          `json:"groups,omitempty"`

	Settings map[string]string `json:"settings,omitempty"`
}

var pluginNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$`)

const (
	pluginLogLines   = 300
	pluginMinBackoff = time.Second
	pluginMaxBackoff = time.Minute
	pluginStableRun  = time.Minute
	pluginStopWait   = 5 * time.Second
)

func ValidatePluginName(name string) error {
	if !pluginNameRe.MatchString(name) {
		return fmt.Errorf("plugin name %q must start with a letter or digit and use only letters, digits, dot, dash and underscore", name)
	}
	return nil
}

func validatePlugins(list []PluginConfig) error {
	seen := map[string]bool{}
	for _, p := range list {
		if !pluginNameRe.MatchString(p.Name) {
			return fmt.Errorf("plugin name %q must start with a letter or digit and use only letters, digits, dot, dash and underscore", p.Name)
		}
		key := strings.ToLower(p.Name)
		if seen[key] {
			return fmt.Errorf("two plugins are named %s", p.Name)
		}
		seen[key] = true
		if strings.TrimSpace(p.Command) == "" {
			return fmt.Errorf("plugin %s has no command", p.Name)
		}
		for k := range p.Env {
			if k == "" || strings.ContainsAny(k, "=\x00") {
				return fmt.Errorf("plugin %s has an invalid environment variable name %q", p.Name, k)
			}
		}
	}
	return nil
}

type pluginManager struct {
	s     *Server
	mu    sync.Mutex
	procs map[string]*pluginProc
}

type pluginProc struct {
	cfg    PluginConfig
	key    string
	cancel context.CancelFunc
	done   chan struct{}

	mu        sync.Mutex
	state     string
	pid       int
	started   time.Time
	restarts  int
	lastExit  string
	nextStart time.Time
	logs      []string
	httpAddr  string
}

type PluginStatus struct {
	Name      string    `json:"name"`
	Command   string    `json:"command"`
	Args      []string  `json:"args,omitempty"`
	Dir       string    `json:"dir"`
	Enabled   bool      `json:"enabled"`
	Admin     bool      `json:"admin"`
	Groups    []string  `json:"groups,omitempty"`
	EnvKeys   []string  `json:"env,omitempty"`
	State     string    `json:"state"`
	PID       int       `json:"pid,omitempty"`
	Started   time.Time `json:"started,omitempty"`
	Restarts  int       `json:"restarts"`
	LastExit  string    `json:"lastExit,omitempty"`
	NextStart time.Time `json:"nextStart,omitempty"`

	Version     string            `json:"version,omitempty"`
	Description string            `json:"description,omitempty"`
	Author      string            `json:"author,omitempty"`
	Homepage    string            `json:"homepage,omitempty"`
	Page        string            `json:"page,omitempty"`
	URL         string            `json:"url,omitempty"`
	AdminOnly   bool              `json:"adminOnly,omitempty"`
	Schema      []PluginSetting   `json:"schema,omitempty"`
	Settings    map[string]string `json:"settings,omitempty"`
}

func pluginKey(p PluginConfig) string {
	b, _ := json.Marshal(p)
	return string(b)
}

func (s *Server) pluginDir(name string) string {
	return filepath.Join(s.DataDir, "plugins", name)
}

func (s *Server) startPlugins() {
	s.plugins = &pluginManager{s: s, procs: map[string]*pluginProc{}}
	s.lmu.Lock()
	s.stoppers = append(s.stoppers, s.plugins.stopAll)
	s.lmu.Unlock()
	s.reloadPlugins()
}

func (s *Server) reloadPlugins() {
	if s.plugins == nil || s.ctx == nil {
		return
	}
	s.plugins.reload(s.Config().Plugins)
}

func (m *pluginManager) reload(list []PluginConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]PluginConfig{}
	for _, p := range list {
		if err := validatePlugins([]PluginConfig{p}); err != nil {
			m.s.log.Error("server plugin skipped", "plugin", p.Name, "err", err)
			continue
		}
		want[strings.ToLower(p.Name)] = p
	}
	for name, pr := range m.procs {
		p, ok := want[name]
		if ok && pr.key == pluginKey(p) {
			continue
		}
		pr.stop()
		delete(m.procs, name)
	}
	for name, p := range want {
		if _, ok := m.procs[name]; ok {
			continue
		}
		pr := &pluginProc{cfg: p, key: pluginKey(p), state: "stopped"}
		m.procs[name] = pr
		if p.Enabled {
			m.launch(pr)
		}
	}
}

func (m *pluginManager) launch(pr *pluginProc) {
	ctx, cancel := context.WithCancel(m.s.ctx)
	pr.cancel = cancel
	pr.done = make(chan struct{})
	go m.supervise(ctx, pr)
}

func (m *pluginManager) restart(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.procs[strings.ToLower(name)]
	if !ok {
		return false
	}
	pr.stop()
	if pr.cfg.Enabled {
		pr.mu.Lock()
		pr.restarts = 0
		pr.mu.Unlock()
		m.launch(pr)
	}
	return true
}

func (m *pluginManager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var wg sync.WaitGroup
	for _, pr := range m.procs {
		wg.Add(1)
		go func(pr *pluginProc) {
			defer wg.Done()
			pr.stop()
		}(pr)
	}
	wg.Wait()
}

func (pr *pluginProc) stop() {
	if pr.cancel == nil {
		return
	}
	pr.cancel()
	<-pr.done
	pr.cancel = nil
	pr.mu.Lock()
	pr.state = "stopped"
	pr.pid = 0
	pr.nextStart = time.Time{}
	pr.mu.Unlock()
}

func (pr *pluginProc) set(fn func()) {
	pr.mu.Lock()
	fn()
	pr.mu.Unlock()
}

func (pr *pluginProc) addLog(line string) {
	if len(line) > 2000 {
		line = line[:2000]
	}
	line = time.Now().Format("2006-01-02 15:04:05") + "  " + line
	pr.mu.Lock()
	pr.logs = append(pr.logs, line)
	if len(pr.logs) > pluginLogLines {
		pr.logs = append(pr.logs[:0], pr.logs[len(pr.logs)-pluginLogLines:]...)
	}
	pr.mu.Unlock()
}

func (m *pluginManager) supervise(ctx context.Context, pr *pluginProc) {
	defer close(pr.done)
	backoff := pluginMinBackoff
	for ctx.Err() == nil {
		began := time.Now()
		err := m.runOnce(ctx, pr)
		if ctx.Err() != nil {
			return
		}
		ran := time.Since(began)
		if ran >= pluginStableRun {
			backoff = pluginMinBackoff
		}
		msg := "exited"
		if err != nil {
			msg = err.Error()
		}
		next := time.Now().Add(backoff)
		pr.set(func() {
			pr.state = "restarting"
			pr.pid = 0
			pr.lastExit = msg
			pr.restarts++
			pr.nextStart = next
		})
		pr.addLog("GolangTAK: plugin " + msg + "; starting again in " + backoff.String())
		m.s.log.Warn("server plugin stopped", "plugin", pr.cfg.Name, "reason", msg, "restartIn", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > pluginMaxBackoff {
			backoff = pluginMaxBackoff
		}
	}
}

func (m *pluginManager) runOnce(ctx context.Context, pr *pluginProc) error {
	s := m.s
	p := pr.cfg
	dir := s.pluginDir(p.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("could not create %s: %w", dir, err)
	}
	work := dir
	if p.Dir != "" {
		work = p.Dir
		if !filepath.IsAbs(work) {
			work = filepath.Join(dir, work)
		}
	}
	command := p.Command
	if strings.ContainsAny(command, `/\`) && !filepath.IsAbs(command) {
		command = filepath.Join(work, command)
	}
	token, err := s.pluginToken(p)
	if err != nil {
		return fmt.Errorf("could not prepare the plugin's API token: %w", err)
	}
	cmd := exec.Command(command, p.Args...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), s.pluginEnv(p, dir, token)...)
	cmd.Env = append(cmd.Env, s.pluginExtraEnv(p, pr)...)
	for k, v := range p.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	pluginSysProcAttr(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	pr.set(func() { pr.state = "starting" })
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	now := time.Now()
	pr.set(func() {
		pr.state = "running"
		pr.pid = cmd.Process.Pid
		pr.started = now
		pr.nextStart = time.Time{}
	})
	pr.addLog(fmt.Sprintf("GolangTAK: started %s (process %d)", command, cmd.Process.Pid))
	s.log.Info("server plugin started", "plugin", p.Name, "pid", cmd.Process.Pid)
	var wg sync.WaitGroup
	pipe := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			pr.addLog(line)
			s.log.Debug("plugin output", "plugin", p.Name, "line", line)
		}
	}
	wg.Add(2)
	go pipe(stdout)
	go pipe(stderr)
	exited := make(chan error, 1)
	go func() {
		wg.Wait()
		exited <- cmd.Wait()
	}()
	select {
	case err := <-exited:
		return describeExit(err)
	case <-ctx.Done():
		pluginTerminate(cmd.Process)
		select {
		case <-exited:
		case <-time.After(pluginStopWait):
			pluginKill(cmd.Process)
			<-exited
		}
		pr.addLog("GolangTAK: plugin stopped")
		s.log.Info("server plugin stopped", "plugin", p.Name)
		return nil
	}
}

func describeExit(err error) error {
	if err == nil {
		return errors.New("exited with status 0")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("exited with status %d", ee.ExitCode())
	}
	return err
}

func (s *Server) pluginEnv(p PluginConfig, dir, token string) []string {
	cfg := s.Config()
	host := "127.0.0.1"
	switch cfg.Bind {
	case "", "0.0.0.0", "::", "[::]":
	default:
		host = strings.Trim(cfg.Bind, "[]")
	}
	base, ws := "", ""
	switch {
	case cfg.Ports.HTTP > 0:
		base = "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.Ports.HTTP))
		ws = "ws://" + net.JoinHostPort(host, strconv.Itoa(cfg.Ports.HTTP))
	case cfg.Ports.Enroll > 0:
		base = "https://" + net.JoinHostPort(host, strconv.Itoa(cfg.Ports.Enroll))
		ws = "wss://" + net.JoinHostPort(host, strconv.Itoa(cfg.Ports.Enroll))
	}
	env := []string{
		"GOLANGTAK_PLUGIN=" + p.Name,
		"GOLANGTAK_PLUGIN_DATA=" + dir,
		"GOLANGTAK_TOKEN=" + token,
		"GOLANGTAK_CA=" + filepath.Join(s.DataDir, "certs", "ca.pem"),
		"GOLANGTAK_VERSION=" + s.Version,
		"GOLANGTAK_SERVER_NAME=" + cfg.Name,
	}
	if base != "" {
		env = append(env, "GOLANGTAK_URL="+base, "GOLANGTAK_STREAM_URL="+ws+"/api/stream")
	}
	if cfg.Ports.TCP > 0 {
		env = append(env, "GOLANGTAK_COT_TCP="+net.JoinHostPort(host, strconv.Itoa(cfg.Ports.TCP)))
	}
	return env
}

func pluginUser(name string) string {
	return "plugin-" + strings.ToLower(name)
}

func (s *Server) pluginToken(p PluginConfig) (string, error) {
	user := pluginUser(p.Name)
	u, ok := s.dir.User(user)
	if !ok {
		var err error
		u, err = s.dir.AddUser(user, NewSecret(24), p.Admin, p.Groups)
		if err != nil {
			return "", err
		}
	}
	if u.Admin != p.Admin || u.Note == "" {
		if _, err := s.dir.UpdateUser(user, func(x *User) error {
			x.Admin = p.Admin
			x.Note = "Account for the server plugin " + p.Name
			return nil
		}); err != nil {
			return "", err
		}
	}
	file := filepath.Join(s.pluginDir(p.Name), ".token")
	if b, err := os.ReadFile(file); err == nil {
		secret := strings.TrimSpace(string(b))
		if _, err := s.dir.useToken(secret, user, "api"); err == nil {
			return secret, nil
		}
	}
	for _, t := range s.dir.Tokens() {
		if t.User == user && t.Kind == "api" {
			s.dir.DeleteToken(t.ID)
		}
	}
	secret, _, err := s.dir.CreateToken(user, "api", "server plugin "+p.Name, 0, 0)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(file, []byte(secret+"\n"), 0o600); err != nil {
		return "", err
	}
	return secret, nil
}

func (m *pluginManager) status() []PluginStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PluginStatus, 0, len(m.procs))
	for _, pr := range m.procs {
		out = append(out, pr.status(m.s))
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (pr *pluginProc) status(s *Server) PluginStatus {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	st := PluginStatus{
		Name: pr.cfg.Name, Command: pr.cfg.Command, Args: pr.cfg.Args, Dir: s.pluginDir(pr.cfg.Name), Enabled: pr.cfg.Enabled,
		Admin: pr.cfg.Admin, Groups: pr.cfg.Groups, State: pr.state, PID: pr.pid, Started: pr.started, Restarts: pr.restarts,
		LastExit: pr.lastExit, NextStart: pr.nextStart,
	}
	if !pr.cfg.Enabled {
		st.State = "disabled"
	}
	for k := range pr.cfg.Env {
		st.EnvKeys = append(st.EnvKeys, k)
	}
	sort.Strings(st.EnvKeys)
	if m := s.pluginManifest(pr.cfg); m != nil {
		st.Version, st.Description, st.Author, st.Homepage, st.AdminOnly, st.Schema = m.Version, m.Description, m.Author, m.Homepage, m.AdminOnly, m.Settings
		if m.HTTP {
			st.Page = firstNonEmpty(m.Page, pr.cfg.Name)
			st.URL = "/plugins/" + pr.cfg.Name + "/"
		}
		st.Settings = s.pluginSettingValues(pr.cfg, m)
		for _, def := range m.Settings {
			if def.Type == "secret" && st.Settings[def.Key] != "" {
				st.Settings[def.Key] = secretMask
			}
		}
	}
	return st
}

func (m *pluginManager) logs(name string) ([]string, bool) {
	m.mu.Lock()
	pr, ok := m.procs[strings.ToLower(name)]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return append([]string(nil), pr.logs...), true
}

func (s *Server) pluginStatusList() []PluginStatus {
	if s.plugins != nil {
		return s.plugins.status()
	}
	var out []PluginStatus
	for _, p := range s.Config().Plugins {
		pr := &pluginProc{cfg: p, state: "stopped"}
		out = append(out, pr.status(s))
	}
	return out
}

func (s *Server) apiServerPluginsList(w http.ResponseWriter, r *http.Request) {
	list := s.pluginStatusList()
	if list == nil {
		list = []PluginStatus{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiServerPluginLogs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.plugins == nil {
		writeJSON(w, http.StatusOK, []string{})
		return
	}
	lines, ok := s.plugins.logs(name)
	if !ok {
		apiError(w, http.StatusNotFound, fmt.Errorf("no server plugin named %s", name))
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, lines)
}

func (s *Server) apiServerPluginAction(w http.ResponseWriter, r *http.Request) {
	name, action := r.PathValue("name"), r.PathValue("action")
	found := false
	for _, p := range s.Config().Plugins {
		if strings.EqualFold(p.Name, name) {
			found = true
		}
	}
	if !found {
		apiError(w, http.StatusNotFound, fmt.Errorf("no server plugin named %s", name))
		return
	}
	switch action {
	case "enable", "disable":
		on := action == "enable"
		if _, err := s.UpdateConfig(func(c *Config) error {
			for i := range c.Plugins {
				if strings.EqualFold(c.Plugins[i].Name, name) {
					c.Plugins[i].Enabled = on
				}
			}
			return nil
		}); err != nil {
			apiError(w, http.StatusInternalServerError, err)
			return
		}
		s.reloadPlugins()
	case "restart":
		if s.plugins != nil {
			s.plugins.restart(name)
		}
	default:
		apiError(w, http.StatusNotFound, fmt.Errorf("unknown action %s", action))
		return
	}
	s.log.Info("server plugin "+action, "plugin", name, "by", identityOf(r).Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

var errPluginLocalOnly = errors.New("server plugins can only be added, changed or removed on the server itself, with the golangtak plugin command or by editing config.json")

func (s *Server) apiServerPluginPut(w http.ResponseWriter, r *http.Request) {
	if identityOf(r).Via != "control" {
		apiError(w, http.StatusForbidden, errPluginLocalOnly)
		return
	}
	var p PluginConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	if name := r.PathValue("name"); !strings.EqualFold(name, p.Name) {
		apiError(w, http.StatusBadRequest, errors.New("the plugin name in the address and the body differ"))
		return
	}
	if _, err := s.UpdateConfig(func(c *Config) error {
		replaced := false
		for i := range c.Plugins {
			if strings.EqualFold(c.Plugins[i].Name, p.Name) {
				c.Plugins[i] = p
				replaced = true
			}
		}
		if !replaced {
			c.Plugins = append(c.Plugins, p)
		}
		return validatePlugins(c.Plugins)
	}); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	s.reloadPlugins()
	s.log.Info("server plugin saved", "plugin", p.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) apiServerPluginDelete(w http.ResponseWriter, r *http.Request) {
	if identityOf(r).Via != "control" {
		apiError(w, http.StatusForbidden, errPluginLocalOnly)
		return
	}
	name := r.PathValue("name")
	found := false
	if _, err := s.UpdateConfig(func(c *Config) error {
		out := c.Plugins[:0]
		for _, p := range c.Plugins {
			if strings.EqualFold(p.Name, name) {
				found = true
				continue
			}
			out = append(out, p)
		}
		c.Plugins = out
		return nil
	}); err != nil {
		apiError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		apiError(w, http.StatusNotFound, fmt.Errorf("no server plugin named %s", name))
		return
	}
	s.reloadPlugins()
	user := pluginUser(name)
	for _, t := range s.dir.Tokens() {
		if t.User == user {
			s.dir.DeleteToken(t.ID)
		}
	}
	if _, ok := s.dir.User(user); ok {
		s.dir.DeleteUser(user)
	}
	os.Remove(filepath.Join(s.pluginDir(name), ".token"))
	s.log.Info("server plugin removed", "plugin", name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
