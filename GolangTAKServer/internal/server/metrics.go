package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"
)

type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"`
}

type promWriter struct {
	b    strings.Builder
	seen map[string]bool
}

func promEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v)
}

func (p *promWriter) metric(name, kind, help string, value float64, labels ...string) {
	if !p.seen[name] {
		p.seen[name] = true
		fmt.Fprintf(&p.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	p.b.WriteString(name)
	if len(labels) > 0 {
		p.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				p.b.WriteByte(',')
			}
			fmt.Fprintf(&p.b, `%s="%s"`, labels[i], promEscape(labels[i+1]))
		}
		p.b.WriteByte('}')
	}
	fmt.Fprintf(&p.b, " %v\n", value)
}

func (s *Server) metricsAllowed(r *http.Request) bool {
	mc := s.Config().Metrics
	if mc.Token != "" {
		h := r.Header.Get("Authorization")
		if scheme, cred, ok := strings.Cut(h, " "); ok && strings.EqualFold(scheme, "bearer") && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(cred)), []byte(mc.Token)) == 1 {
			return true
		}
	}
	id, _, err := s.resolveIdentity(r)
	return err == nil && id != nil && id.Admin
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.Config().Metrics.Enabled {
		http.NotFound(w, r)
		return
	}
	if !s.metricsAllowed(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="GolangTAKServer metrics"`)
		http.Error(w, "use the metrics token or an administrator account", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(s.metricsText()))
}

func (s *Server) metricsText() string {
	p := &promWriter{seen: map[string]bool{}}
	const pre = "golangtakserver_"
	p.metric(pre+"info", "gauge", "Version information.", 1, "version", s.Version, "go", runtime.Version())
	p.metric(pre+"uptime_seconds", "gauge", "Seconds since the server started.", time.Since(s.Started).Seconds())

	kinds := map[string]int{}
	var queueDrops, rateDrops uint64
	for _, c := range s.hub.Clients() {
		kinds[c.Kind]++
		queueDrops += c.drops.Load()
		rateDrops += c.rateDrops.Load()
	}
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) == 0 {
		p.metric(pre+"clients", "gauge", "Connected clients by connection type.", 0, "kind", "tcp")
	}
	for _, k := range names {
		p.metric(pre+"clients", "gauge", "Connected clients by connection type.", float64(kinds[k]), "kind", k)
	}
	p.metric(pre+"messages_received_total", "counter", "CoT messages accepted from clients, links and feeds.", float64(s.hub.Events.Load()))
	p.metric(pre+"messages_delivered_total", "counter", "CoT messages queued to clients.", float64(s.hub.Delivered.Load()))
	p.metric(pre+"bytes_sent_total", "counter", "Bytes written to stream clients.", float64(s.hub.Bytes.Load()))
	p.metric(pre+"rate_limited_messages_total", "counter", "Messages dropped by rate limits.", float64(s.hub.RateDropped.Load()))
	p.metric(pre+"rate_limited_connections_total", "counter", "Connections refused by the connection rate limit.", float64(s.hub.RateRefused.Load()))
	p.metric(pre+"client_queue_drops", "gauge", "Messages dropped because a connected client's send queue was full.", float64(queueDrops))
	p.metric(pre+"cached_items", "gauge", "Items kept for replay to new clients.", float64(len(s.hub.Cached())))
	p.metric(pre+"emergencies_active", "gauge", "Active emergency alerts.", float64(len(s.hub.Emergencies())))
	p.metric(pre+"missions", "gauge", "Missions (data sync feeds).", float64(len(s.missions.All())))
	p.metric(pre+"files", "gauge", "Stored files and data packages.", float64(len(s.res.All())))
	p.metric(pre+"users", "gauge", "User accounts.", float64(len(s.dir.Users())))
	p.metric(pre+"pending_chats", "gauge", "Chat messages waiting for offline recipients.", float64(len(s.PendingChats())))
	if s.live != nil {
		streams := s.live.reg.List()
		viewers := 0
		for _, st := range streams {
			viewers += st.Readers()
		}
		p.metric(pre+"video_streams", "gauge", "Live video streams.", float64(len(streams)))
		p.metric(pre+"video_viewers", "gauge", "Live video viewers.", float64(viewers))
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.perf.mu.RLock()
	st := s.perf.latest
	s.perf.mu.RUnlock()
	if st.ProcRSS > 0 {
		p.metric("process_resident_memory_bytes", "gauge", "Resident memory size in bytes.", float64(st.ProcRSS))
	}
	if st.HaveProc {
		p.metric("process_cpu_seconds_total", "counter", "Total user and system CPU time spent in seconds.", st.ProcCPU.Seconds())
	}
	p.metric("go_goroutines", "gauge", "Number of goroutines that currently exist.", float64(runtime.NumGoroutine()))
	p.metric("go_memstats_heap_inuse_bytes", "gauge", "Number of heap bytes that are in use.", float64(ms.HeapInuse))
	p.metric("go_memstats_sys_bytes", "gauge", "Number of bytes obtained from the system.", float64(ms.Sys))
	p.metric("go_gc_cycles_total", "counter", "Completed garbage collection cycles.", float64(ms.NumGC))
	if st.HaveAvail {
		p.metric(pre+"system_memory_total_bytes", "gauge", "Total system memory.", float64(st.MemTotal))
		p.metric(pre+"system_memory_available_bytes", "gauge", "Available system memory.", float64(st.MemAvail))
	}
	if len(st.Load) > 0 {
		p.metric(pre+"system_load1", "gauge", "One minute load average.", st.Load[0])
	}
	if st.HaveDisk {
		p.metric(pre+"data_disk_total_bytes", "gauge", "Size of the disk holding the data directory.", float64(st.DiskTotal))
		p.metric(pre+"data_disk_free_bytes", "gauge", "Free space on the disk holding the data directory.", float64(st.DiskFree))
	}
	return p.b.String()
}
