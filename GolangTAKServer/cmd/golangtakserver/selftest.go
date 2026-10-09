package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/server"
)

type checkResult struct {
	name string
	err  error
}

func pingStream(conn net.Conn) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(cot.Ping("golangtakserver-selftest").XML()); err != nil {
		return err
	}
	want := []byte(`type="t-x-c-t-r"`)
	buf := make([]byte, 0, 64<<10)
	tmp := make([]byte, 16<<10)
	for {
		n, err := conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if bytes.Contains(buf, want) {
			return nil
		}
		if len(buf) > 32<<10 {
			buf = append(buf[:0], buf[len(buf)-len(want):]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("the server closed the connection without answering")
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return errors.New("no answer to a ping within 10 seconds")
			}
			return err
		}
	}
}

func httpCheck(url string, tlsCfg *tls.Config, want []byte) error {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tlsCfg, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	resp, err := hc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if want != nil && !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(want)) {
		return errors.New("unexpected response")
	}
	return nil
}

func selfTest(dir string, cfg server.Config) []checkResult {
	var out []checkResult
	add := func(name string, err error) { out = append(out, checkResult{name, err}) }
	host := localHost(cfg)
	addr := func(port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
	caPEM, caErr := os.ReadFile(filepath.Join(dir, "certs", "ca.pem"))
	pool := x509.NewCertPool()
	if caErr == nil {
		pool.AppendCertsFromPEM(caPEM)
	}
	cert, certErr := tls.LoadX509KeyPair(filepath.Join(dir, "certs", "selftest.pem"), filepath.Join(dir, "certs", "selftest.key"))
	clientTLS := func() (*tls.Config, error) {
		if caErr != nil {
			return nil, caErr
		}
		if certErr != nil {
			return nil, certErr
		}
		return &tls.Config{RootCAs: pool, ServerName: cfg.Address, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	if cfg.Ports.TLS > 0 {
		name := fmt.Sprintf("TAK SSL port %d", cfg.Ports.TLS)
		tc, err := clientTLS()
		if err == nil {
			var conn *tls.Conn
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr(cfg.Ports.TLS), tc)
			if err == nil {
				err = pingStream(conn)
			}
		}
		add(name, err)
	}
	if cfg.Ports.TCP > 0 && cfg.AllowAnonymous {
		conn, err := net.DialTimeout("tcp", addr(cfg.Ports.TCP), 5*time.Second)
		if err == nil {
			err = pingStream(conn)
		}
		add(fmt.Sprintf("TAK TCP port %d", cfg.Ports.TCP), err)
	}
	if cfg.Ports.HTTP > 0 {
		add(fmt.Sprintf("Web port %d", cfg.Ports.HTTP), httpCheck("http://"+addr(cfg.Ports.HTTP)+"/api/ca.pem", nil, caPEM))
	}
	if cfg.Ports.Enroll > 0 {
		add(fmt.Sprintf("Enrollment port %d", cfg.Ports.Enroll), httpCheck("https://"+addr(cfg.Ports.Enroll)+"/api/ca.pem", &tls.Config{RootCAs: pool, ServerName: cfg.Address, MinVersion: tls.VersionTLS12}, caPEM))
	}
	if cfg.Ports.HTTPS > 0 {
		tc, err := clientTLS()
		if err == nil {
			err = httpCheck("https://"+addr(cfg.Ports.HTTPS)+"/Marti/api/clientEndPoints", tc, nil)
		}
		add(fmt.Sprintf("HTTPS port %d", cfg.Ports.HTTPS), err)
	}
	if cfg.Ports.WebSocket > 0 {
		add(fmt.Sprintf("WebSocket port %d", cfg.Ports.WebSocket), httpCheck("http://"+addr(cfg.Ports.WebSocket)+"/", nil, nil))
	}
	if cfg.Ports.API > 0 {
		add(fmt.Sprintf("FTS-compatible API port %d", cfg.Ports.API), httpCheck("http://"+addr(cfg.Ports.API)+"/Alive", nil, nil))
	}
	if cfg.Federation.Enabled && cfg.Ports.Federation > 0 {
		conn, err := net.DialTimeout("tcp", addr(cfg.Ports.Federation), 5*time.Second)
		if err == nil {
			conn.Close()
		}
		add(fmt.Sprintf("Federation port %d", cfg.Ports.Federation), err)
	}
	return out
}

func cmdSelfTest(a *args) error {
	dir := dataDir(a)
	cfg, err := server.LoadConfig(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "selftest.key")); err != nil {
		if !isAdmin() {
			if eerr := elevate(invocation); eerr == nil {
				os.Exit(0)
			}
		}
		return fmt.Errorf("cannot read the self-test certificate: %w", err)
	}
	failed := 0
	for _, r := range selfTest(dir, cfg) {
		if r.err != nil {
			failed++
			fmt.Printf("  %-32s FAILED: %v\n", r.name, r.err)
		} else {
			fmt.Printf("  %-32s ok\n", r.name)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed; is the server running? ('golangtakserver status')", failed)
	}
	fmt.Println("All checks passed.")
	return nil
}
