package server

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestPerformanceAPI(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("perfadmin", "perf-password", true, nil)
	secret, _, err := s.dir.CreateToken("perfadmin", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.samplePerf()
	time.Sleep(50 * time.Millisecond)
	s.samplePerf()
	url := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.HTTP) + "/api/performance"
	if st, _ := doReq(t, http.DefaultClient, "GET", url, nil, nil); st != http.StatusUnauthorized {
		t.Fatalf("performance without sign-in returned %d", st)
	}
	st, body := doReq(t, http.DefaultClient, "GET", url, nil, map[string]string{"Authorization": "Bearer " + secret})
	if st != 200 {
		t.Fatalf("performance: %d %s", st, body)
	}
	var pf struct {
		Current *PerfSample  `json:"current"`
		History []PerfSample `json:"history"`
		System  struct {
			CPUs        int    `json:"cpus"`
			MemoryTotal uint64 `json:"memoryTotal"`
			Disk        *struct {
				Total uint64 `json:"total"`
			} `json:"disk"`
		} `json:"system"`
		Process struct {
			Memory      uint64 `json:"memory"`
			CPUMeasured bool   `json:"cpuMeasured"`
		} `json:"process"`
	}
	if err := json.Unmarshal(body, &pf); err != nil {
		t.Fatal(err)
	}
	if pf.Current == nil || len(pf.History) == 0 || pf.System.CPUs != runtime.NumCPU() || pf.Process.Memory == 0 {
		t.Fatalf("incomplete performance data: %s", body)
	}
	if pf.Current.CPU < 0 || pf.Current.CPU > 100 || pf.Current.SystemCPU < 0 || pf.Current.SystemCPU > 100 {
		t.Fatalf("cpu out of range: %+v", pf.Current)
	}
	switch runtime.GOOS {
	case "linux", "windows", "darwin", "freebsd":
		if pf.System.MemoryTotal == 0 || pf.System.Disk == nil || pf.System.Disk.Total == 0 || !pf.Process.CPUMeasured {
			t.Fatalf("system figures missing on %s: %s", runtime.GOOS, body)
		}
	}
}
