package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/takproto"
)

type benchOptions struct {
	addr     string
	clients  int
	every    time.Duration
	duration time.Duration
	ramp     time.Duration
	tls      *tls.Config
	out      io.Writer
	tick     time.Duration
}

type benchStats struct {
	connected  atomic.Int64
	failed     atomic.Int64
	dropped    atomic.Int64
	sent       atomic.Int64
	received   atomic.Int64
	expected   atomic.Int64
	bytesIn    atomic.Int64
	mu         sync.Mutex
	latencies  []time.Duration
	connectDur []time.Duration
	firstErr   atomic.Value
}

func (st *benchStats) fail(err error) {
	st.failed.Add(1)
	st.firstErr.CompareAndSwap(nil, err.Error())
}

type benchResult struct {
	Clients, Connected, Failed, Dropped int64
	Sent, Received                      int64
	Expected                            float64
	Elapsed                             time.Duration
	P50, P95, P99, Max                  time.Duration
	ConnectP50                          time.Duration
	FirstError                          string
}

var benchMarker = []byte(`<__bench t="`)

func benchLatency(frame takproto.Frame, now, since time.Time) (time.Duration, bool) {
	data := frame.Data
	if frame.Proto {
		msg, err := takproto.Unmarshal(frame.Data)
		if err != nil || msg.Event == nil {
			return 0, false
		}
		n := msg.Event.D("__bench")
		if n == nil {
			return 0, false
		}
		data = []byte(`<__bench t="` + n.Attr("t") + `"`)
	}
	i := bytes.Index(data, benchMarker)
	if i < 0 {
		return 0, false
	}
	rest := data[i+len(benchMarker):]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return 0, false
	}
	ns, err := strconv.ParseInt(string(rest[:j]), 10, 64)
	if err != nil {
		return 0, false
	}
	sent := time.Unix(0, ns)
	if sent.Before(since) {
		return 0, false
	}
	return now.Sub(sent), true
}

func benchEvent(uid, callsign string, lat, lon float64, now time.Time) []byte {
	e := cot.New(uid, "a-f-G-U-C", "m-g", 2*time.Minute)
	e.Point = cot.Point{Lat: lat, Lon: lon, Hae: 0, Ce: 10, Le: 10}
	e.Detail.AddNew("contact", "callsign", callsign)
	e.Detail.AddNew("__group", "name", "Cyan", "role", "Team Member")
	e.Detail.AddNew("__bench", "t", strconv.FormatInt(now.UnixNano(), 10))
	return e.XML()
}

func benchClient(o benchOptions, id int, st *benchStats, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	d := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if o.tls != nil {
		conn, err = tls.DialWithDialer(d, "tcp", o.addr, o.tls)
	} else {
		conn, err = d.Dial("tcp", o.addr)
	}
	if err != nil {
		st.fail(err)
		return
	}
	defer conn.Close()
	st.mu.Lock()
	st.connectDur = append(st.connectDur, time.Since(start))
	st.mu.Unlock()
	st.connected.Add(1)
	joined := time.Now()
	uid := fmt.Sprintf("golangtak-bench-%05d", id)
	callsign := fmt.Sprintf("BENCH-%d", id)
	lat := 38.8 + rand.Float64()*0.4
	lon := -77.2 + rand.Float64()*0.4
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		r := takproto.NewReader(conn, 1<<20)
		var local []time.Duration
		for {
			fr, err := r.Next()
			if err != nil {
				break
			}
			st.bytesIn.Add(int64(len(fr.Data)))
			if lat, ok := benchLatency(fr, time.Now(), joined); ok {
				st.received.Add(1)
				if len(local) < 200000 {
					local = append(local, lat)
				}
			}
		}
		st.mu.Lock()
		st.latencies = append(st.latencies, local...)
		st.mu.Unlock()
	}()
	jitter := time.Duration(rand.Int64N(int64(o.every)))
	timer := time.NewTimer(jitter)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			time.Sleep(500 * time.Millisecond)
			conn.Close()
			<-readDone
			return
		case <-readDone:
			select {
			case <-stop:
			default:
				st.dropped.Add(1)
			}
			return
		case <-timer.C:
		}
		lat += (rand.Float64() - 0.5) * 0.0005
		lon += (rand.Float64() - 0.5) * 0.0005
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(benchEvent(uid, callsign, lat, lon, time.Now())); err != nil {
			st.dropped.Add(1)
			st.firstErr.CompareAndSwap(nil, err.Error())
			conn.Close()
			<-readDone
			return
		}
		st.sent.Add(1)
		st.expected.Add(max(0, st.connected.Load()-st.dropped.Load()-1))
		timer.Reset(o.every)
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	return sorted[max(0, min(i, len(sorted)-1))]
}

func runBench(o benchOptions) benchResult {
	st := &benchStats{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()
	done := make(chan struct{})
	go func() {
		if o.tick <= 0 {
			return
		}
		t := time.NewTicker(o.tick)
		defer t.Stop()
		var lastSent, lastRecv int64
		last := time.Now()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				s, r := st.sent.Load(), st.received.Load()
				secs := now.Sub(last).Seconds()
				fmt.Fprintf(o.out, "  %5.0fs  %d connected  %d failed  %.0f sent/s  %.0f delivered/s\n", now.Sub(start).Seconds(), st.connected.Load()-st.dropped.Load(), st.failed.Load()+st.dropped.Load(), float64(s-lastSent)/secs, float64(r-lastRecv)/secs)
				lastSent, lastRecv, last = s, r, now
			}
		}
	}()
	gap := time.Duration(0)
	if o.clients > 1 {
		gap = o.ramp / time.Duration(o.clients)
	}
	for i := 0; i < o.clients; i++ {
		wg.Add(1)
		go benchClient(o, i+1, st, stop, &wg)
		if gap > 0 {
			time.Sleep(gap)
		}
	}
	if rest := o.duration - time.Since(start); rest > 0 {
		time.Sleep(rest)
	}
	close(stop)
	wg.Wait()
	close(done)
	elapsed := time.Since(start)
	res := benchResult{Clients: int64(o.clients), Connected: st.connected.Load(), Failed: st.failed.Load(), Dropped: st.dropped.Load(), Sent: st.sent.Load(), Received: st.received.Load(), Elapsed: elapsed}
	res.Expected = float64(st.expected.Load())
	slices.Sort(st.latencies)
	res.P50, res.P95, res.P99 = percentile(st.latencies, 0.50), percentile(st.latencies, 0.95), percentile(st.latencies, 0.99)
	if len(st.latencies) > 0 {
		res.Max = st.latencies[len(st.latencies)-1]
	}
	slices.Sort(st.connectDur)
	res.ConnectP50 = percentile(st.connectDur, 0.50)
	if v, ok := st.firstErr.Load().(string); ok {
		res.FirstError = v
	}
	return res
}

func benchTLS(a *args) (*tls.Config, error) {
	host := a.val("host")
	if host == "" {
		host = "127.0.0.1"
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if a.on("insecure") {
		cfg.InsecureSkipVerify = true
	}
	if f := a.val("cert"); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		p, err := pki.DecodePKCS12(raw, firstNonEmptyArg(a.val("cert-password"), "atakatak"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		chain := [][]byte{p.Cert.Raw}
		pool := x509.NewCertPool()
		for _, c := range p.Certs {
			if c.IsCA {
				pool.AddCert(c)
			} else if !c.Equal(p.Cert) {
				chain = append(chain, c.Raw)
			}
		}
		cfg.Certificates = []tls.Certificate{{Certificate: chain, PrivateKey: p.Key, Leaf: p.Cert}}
		if !cfg.InsecureSkipVerify {
			cfg.RootCAs = pool
		}
	}
	if f := a.val("trust"); f != "" && !cfg.InsecureSkipVerify {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if p, err := pki.DecodePKCS12(raw, firstNonEmptyArg(a.val("trust-password"), "atakatak")); err == nil {
			for _, c := range p.Certs {
				pool.AddCert(c)
			}
			if p.Cert != nil {
				pool.AddCert(p.Cert)
			}
		} else if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("%s: not a PEM or .p12 trust store", f)
		}
		cfg.RootCAs = pool
	}
	if len(cfg.Certificates) == 0 {
		return nil, errors.New("TLS needs a client certificate: pass --cert USER.p12 (from 'golangtak user package NAME') or use plain TCP")
	}
	return cfg, nil
}

func firstNonEmptyArg(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func parseBenchDuration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(f * float64(time.Second)), nil
	}
	return time.ParseDuration(s)
}

func cmdBench(a *args) error {
	host := firstNonEmptyArg(a.val("host"), "127.0.0.1")
	useTLS := a.on("tls") || a.has("cert")
	port := 8087
	if useTLS {
		port = 8089
	}
	if p := a.val("port"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return fmt.Errorf("--port %q is not a port number", p)
		}
		port = n
	}
	clients := 100
	if v := a.val("clients"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100000 {
			return fmt.Errorf("--clients must be between 1 and 100000")
		}
		clients = n
	}
	every, err := parseBenchDuration(a.val("every"), time.Second)
	if err != nil || every < 10*time.Millisecond {
		return fmt.Errorf("--every must be at least 0.01 seconds")
	}
	duration, err := parseBenchDuration(a.val("duration"), 30*time.Second)
	if err != nil || duration < time.Second {
		return fmt.Errorf("--duration must be at least 1 second")
	}
	ramp, err := parseBenchDuration(a.val("ramp"), min(duration/4, time.Duration(clients)*20*time.Millisecond))
	if err != nil || ramp < 0 || ramp >= duration {
		return fmt.Errorf("--ramp must be shorter than --duration")
	}
	o := benchOptions{addr: net.JoinHostPort(host, strconv.Itoa(port)), clients: clients, every: every, duration: duration, ramp: ramp, out: os.Stdout, tick: 5 * time.Second}
	if useTLS {
		if o.tls, err = benchTLS(a); err != nil {
			return err
		}
	}
	proto := "TCP"
	if useTLS {
		proto = "TLS"
	}
	fmt.Printf("Load test: %d clients over %s to %s, each sending a position every %s for %s.\n", clients, proto, o.addr, every, duration)
	res := runBench(o)
	printBench(os.Stdout, res)
	if res.Connected == 0 {
		return errors.New("no client could connect")
	}
	return nil
}

func printBench(w io.Writer, r benchResult) {
	secs := r.Elapsed.Seconds()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Clients     %d connected of %d", r.Connected, r.Clients)
	if r.Failed > 0 || r.Dropped > 0 {
		fmt.Fprintf(w, ", %d could not connect, %d disconnected early", r.Failed, r.Dropped)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Connect     %s median\n", r.ConnectP50.Round(100*time.Microsecond))
	fmt.Fprintf(w, "Sent        %d positions (%.0f per second)\n", r.Sent, float64(r.Sent)/secs)
	fmt.Fprintf(w, "Delivered   %d copies (%.0f per second)", r.Received, float64(r.Received)/secs)
	if r.Expected > 0 {
		fmt.Fprintf(w, ", %.1f%% of the %.0f expected if every client sees every other one online", 100*float64(r.Received)/r.Expected, r.Expected)
	}
	fmt.Fprintln(w)
	if r.Received > 0 {
		fmt.Fprintf(w, "Latency     %s median, %s p95, %s p99, %s max\n", r.P50.Round(100*time.Microsecond), r.P95.Round(100*time.Microsecond), r.P99.Round(100*time.Microsecond), r.Max.Round(100*time.Microsecond))
	}
	if r.FirstError != "" {
		fmt.Fprintf(w, "First error %s\n", r.FirstError)
		if r.Failed > 0 && (strings.Contains(r.FirstError, "reset") || strings.Contains(r.FirstError, "refused") || strings.Contains(r.FirstError, "EOF")) {
			fmt.Fprintln(w, "            The server may be limiting connections per address; raise it with 'golangtak config set limits.maxPerIP 0' while testing.")
		}
	}
	if r.Expected > 0 && float64(r.Received) < 0.5*r.Expected {
		fmt.Fprintln(w, "            Fewer copies than expected usually means the clients are in different groups, or anonymous TCP is off.")
	}
}
