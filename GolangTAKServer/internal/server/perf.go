package server

import (
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	perfInterval = 2 * time.Second
	perfKeep     = 300
)

type osStats struct {
	MemTotal  uint64
	MemAvail  uint64
	HaveAvail bool
	CPUBusy   uint64
	CPUTotal  uint64
	HaveCPU   bool
	Load      []float64
	ProcCPU   time.Duration
	HaveProc  bool
	ProcRSS   uint64
	DiskTotal uint64
	DiskFree  uint64
	HaveDisk  bool
}

type PerfSample struct {
	Time       int64   `json:"t"`
	CPU        float64 `json:"cpu"`
	SystemCPU  float64 `json:"systemCpu"`
	Memory     uint64  `json:"memory"`
	SystemUsed uint64  `json:"systemUsed"`
	Clients    int     `json:"clients"`
	Messages   float64 `json:"messages"`
	BytesOut   float64 `json:"bytesOut"`
	Goroutines int     `json:"goroutines"`
}

type perfSampler struct {
	mu       sync.RWMutex
	samples  []PerfSample
	last     osStats
	lastWall time.Time
	lastEv   uint64
	lastBy   uint64
	latest   osStats
}

func (s *Server) perfLoop() {
	defer s.wg.Done()
	s.samplePerf()
	t := time.NewTicker(perfInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.samplePerf()
		}
	}
}

func (s *Server) samplePerf() {
	p := s.perf
	now := time.Now()
	st := readOSStats(s.DataDir)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	ev, by := s.hub.Events.Load(), s.hub.Bytes.Load()
	sample := PerfSample{Time: now.UnixMilli(), Clients: s.hub.Count(), Goroutines: runtime.NumGoroutine()}
	sample.Memory = st.ProcRSS
	if sample.Memory == 0 {
		sample.Memory = ms.Sys
	}
	if st.MemTotal > 0 && st.HaveAvail && st.MemAvail <= st.MemTotal {
		sample.SystemUsed = st.MemTotal - st.MemAvail
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.lastWall.IsZero() {
		dt := now.Sub(p.lastWall).Seconds()
		if dt > 0 {
			if st.HaveProc && p.last.HaveProc {
				sample.CPU = clampPct((st.ProcCPU - p.last.ProcCPU).Seconds() / (dt * float64(runtime.NumCPU())) * 100)
			}
			if st.HaveCPU && p.last.HaveCPU && st.CPUTotal > p.last.CPUTotal {
				sample.SystemCPU = clampPct(float64(st.CPUBusy-p.last.CPUBusy) / float64(st.CPUTotal-p.last.CPUTotal) * 100)
			}
			if ev >= p.lastEv {
				sample.Messages = float64(ev-p.lastEv) / dt
			}
			if by >= p.lastBy {
				sample.BytesOut = float64(by-p.lastBy) / dt
			}
		}
		p.samples = append(p.samples, sample)
		if len(p.samples) > perfKeep {
			p.samples = append(p.samples[:0], p.samples[len(p.samples)-perfKeep:]...)
		}
	}
	p.last, p.latest, p.lastWall, p.lastEv, p.lastBy = st, st, now, ev, by
}

func clampPct(v float64) float64 {
	if v < 0 || v != v {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func (s *Server) apiPerformance(w http.ResponseWriter, r *http.Request) {
	p := s.perf
	p.mu.RLock()
	hist := append([]PerfSample(nil), p.samples...)
	st := p.latest
	p.mu.RUnlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	host, _ := os.Hostname()
	var cur *PerfSample
	if len(hist) > 0 {
		cur = &hist[len(hist)-1]
	}
	sys := map[string]any{"cpus": runtime.NumCPU(), "os": runtime.GOOS, "arch": runtime.GOARCH, "hostname": host}
	if st.MemTotal > 0 {
		sys["memoryTotal"] = st.MemTotal
		if st.HaveAvail {
			sys["memoryAvailable"] = st.MemAvail
		}
	}
	if len(st.Load) == 3 {
		sys["load"] = st.Load
	}
	if st.HaveDisk {
		sys["disk"] = map[string]any{"path": s.DataDir, "total": st.DiskTotal, "free": st.DiskFree}
	}
	sys["cpuMeasured"] = st.HaveCPU
	writeJSON(w, http.StatusOK, map[string]any{
		"interval": perfInterval.Seconds(),
		"current":  cur,
		"history":  hist,
		"system":   sys,
		"process": map[string]any{
			"pid": os.Getpid(), "uptimeSeconds": int64(time.Since(s.Started).Seconds()), "cpuMeasured": st.HaveProc,
			"memory": func() uint64 {
				if st.ProcRSS > 0 {
					return st.ProcRSS
				}
				return ms.Sys
			}(),
			"memoryIsRss": st.ProcRSS > 0,
		},
		"runtime": map[string]any{
			"go": runtime.Version(), "goroutines": runtime.NumGoroutine(), "heapInUse": ms.HeapInuse, "heapObjects": ms.HeapObjects,
			"reserved": ms.Sys, "gcCycles": ms.NumGC, "gcPauseTotalMs": float64(ms.PauseTotalNs) / 1e6,
		},
		"traffic": map[string]any{"events": s.hub.Events.Load(), "delivered": s.hub.Delivered.Load(), "bytesOut": s.hub.Bytes.Load(), "clients": s.hub.Count(), "rateDropped": s.hub.RateDropped.Load(), "rateRefused": s.hub.RateRefused.Load()},
	})
}
