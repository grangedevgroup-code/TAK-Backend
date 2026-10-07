package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/server"
)

type client struct {
	dataDir string
	local   *server.Server
	base    string
	token   string
	hc      *http.Client
}

func openClient(dataDir string) (*client, error) {
	if _, err := os.Stat(server.ConfigPath(dataDir)); err != nil {
		if errors.Is(err, fs.ErrPermission) && !isAdmin() {
			if eerr := elevate(invocation); eerr == nil {
				os.Exit(0)
			}
			return nil, err
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no GolangTAK data in %s yet; run 'golangtak install' (or 'golangtak run') first, or pass --data DIR", dataDir)
		}
		return nil, err
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		s, err := server.New(dataDir, server.Options{Version: version})
		if err == nil {
			return &client{dataDir: dataDir, local: s}, nil
		}
		if errors.Is(err, fs.ErrPermission) && !isAdmin() {
			if eerr := elevate(invocation); eerr == nil {
				os.Exit(0)
			}
			return nil, err
		}
		if !errors.Is(err, server.ErrRunning) {
			return nil, err
		}
		c, rerr := remoteClient(dataDir)
		if rerr == nil {
			return c, nil
		}
		if errors.Is(rerr, fs.ErrPermission) && !isAdmin() {
			if eerr := elevate(invocation); eerr == nil {
				os.Exit(0)
			}
			return nil, rerr
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the server is running but did not answer: %w", rerr)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func localHost(cfg server.Config) string {
	switch cfg.Bind {
	case "", "0.0.0.0", "::", "[::]":
		return "127.0.0.1"
	}
	return strings.Trim(cfg.Bind, "[]")
}

func remoteClient(dataDir string) (*client, error) {
	tok, err := os.ReadFile(server.ControlTokenPath(dataDir))
	if err != nil {
		return nil, err
	}
	cfg, err := server.LoadConfig(dataDir)
	if err != nil {
		return nil, err
	}
	host := localHost(cfg)
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second}
	c := &client{dataDir: dataDir, token: strings.TrimSpace(string(tok)), hc: &http.Client{Transport: tr, Timeout: 10 * time.Minute}}
	switch {
	case cfg.Ports.HTTP > 0:
		c.base = "http://" + net.JoinHostPort(host, strconv.Itoa(cfg.Ports.HTTP))
	case cfg.Ports.Enroll > 0 || cfg.Ports.HTTPS > 0:
		port := cfg.Ports.Enroll
		if port == 0 {
			port = cfg.Ports.HTTPS
		}
		pool := x509.NewCertPool()
		if pem, err := os.ReadFile(filepath.Join(dataDir, "certs", "ca.pem")); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
		c.base = "https://" + net.JoinHostPort(host, strconv.Itoa(port))
	default:
		return nil, errors.New("all web ports are disabled in config.json; stop the server to manage it offline")
	}
	st, body, _, err := c.do(http.MethodGet, "/api/me", nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("server refused the local control token: %s", apiError(st, body))
	}
	return c, nil
}

func (c *client) close() {
	if c.local != nil {
		c.local.Stop()
		c.local = nil
	}
}

func (c *client) online() bool { return c.local == nil }

func (c *client) do(method, path string, body []byte) (int, []byte, http.Header, error) {
	if c.local != nil {
		st, b, h := c.local.LocalRequest(method, path, body)
		return st, b, h, nil
	}
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header, err
}

func apiError(status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" || len(msg) > 300 {
		msg = http.StatusText(status)
	}
	return errors.New(msg)
}

func (c *client) call(method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	st, b, _, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	if st >= 400 {
		return apiError(st, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func withClient(a *args, fn func(c *client) error) error {
	c, err := openClient(dataDir(a))
	if err != nil {
		return err
	}
	defer c.close()
	return fn(c)
}
