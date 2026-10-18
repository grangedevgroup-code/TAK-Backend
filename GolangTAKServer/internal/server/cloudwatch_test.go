package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/aws"
)

func TestCloudWatchExport(t *testing.T) {
	var mu sync.Mutex
	var forms []url.Values
	var badSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		when, _ := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
		check.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		aws.Sign(check, body, aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "secret-key-value"}, "us-west-2", "monitoring", when)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		if check.Header.Get("Authorization") != r.Header.Get("Authorization") {
			badSig = r.Header.Get("Authorization")
		}
		forms = append(forms, form)
		mu.Unlock()
		w.Write([]byte(`<PutMetricDataResponse/>`))
	}))
	defer srv.Close()
	s := newTestServer(t, func(c *Config) {
		c.Metrics.CloudWatch = CloudWatchConfig{Enabled: true, Namespace: "takserver-test", Name: "test-node", Region: "us-west-2", StepSeconds: 1, BatchSize: 5,
			Endpoint: srv.URL + "/", AccessKeyID: "AKIDTEST", SecretAccessKey: "secret-key-value"}
	})
	deadline := time.Now().Add(15 * time.Second)
	var counterSeen bool
	for time.Now().Before(deadline) && !counterSeen {
		time.Sleep(300 * time.Millisecond)
		mu.Lock()
		for _, f := range forms {
			for k, v := range f {
				if strings.HasSuffix(k, ".MetricName") && v[0] == "golangtakserver_messages_received_total" {
					counterSeen = true
				}
			}
		}
		mu.Unlock()
	}
	mu.Lock()
	defer mu.Unlock()
	if badSig != "" {
		t.Fatalf("request signature did not verify: %s", badSig)
	}
	if !counterSeen {
		t.Fatalf("no counter after two pushes; %d requests", len(forms))
	}
	f := forms[0]
	if f.Get("Action") != "PutMetricData" || f.Get("Namespace") != "takserver-test" || f.Get("Version") != "2010-08-01" {
		t.Fatalf("request %v", f)
	}
	members := 0
	var users bool
	for k, v := range f {
		if strings.HasSuffix(k, ".MetricName") {
			members++
			pre := strings.TrimSuffix(k, "MetricName")
			if v[0] == "golangtakserver_users" {
				users = f.Get(pre+"Unit") == "None" && f.Get(pre+"Dimensions.member.1.Name") == "Name" && f.Get(pre+"Dimensions.member.1.Value") == "test-node"
			}
			if strings.HasSuffix(v[0], "_info") {
				t.Fatalf("info metric sent: %s", v[0])
			}
		}
	}
	if members == 0 || members > 5 {
		t.Fatalf("batch of %d metrics, want 1-5", members)
	}
	found := users
	for _, g := range forms[1:] {
		for k, v := range g {
			if strings.HasSuffix(k, ".MetricName") && v[0] == "golangtakserver_users" {
				pre := strings.TrimSuffix(k, "MetricName")
				found = found || (g.Get(pre+"Dimensions.member.1.Value") == "test-node")
			}
		}
	}
	if !found {
		t.Fatal("users metric with the Name dimension not sent")
	}
	admin := adminHeaders(t, s)
	st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/metrics/cloudwatch"), nil, admin)
	var status map[string]any
	json.Unmarshal(b, &status)
	if st != http.StatusOK || status["lastError"] != "" || status["lastPush"] == nil || status["metricsSent"].(float64) == 0 {
		t.Fatalf("status %d %s", st, b)
	}
	st, b = doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/settings"), nil, admin)
	if st != http.StatusOK || strings.Contains(string(b), "secret-key-value") {
		t.Fatal("settings returned the CloudWatch secret key")
	}
}

func TestCloudWatchUnits(t *testing.T) {
	for _, c := range [][3]string{{"golangtakserver_bytes_sent_total", "counter", "Bytes"}, {"process_cpu_seconds_total", "counter", "Seconds"}, {"golangtakserver_messages_received_total", "counter", "Count"}, {"golangtakserver_users", "gauge", "None"}} {
		if got := cloudWatchUnit(c[0], c[1]); got != c[2] {
			t.Errorf("%s: %s, want %s", c[0], got, c[2])
		}
	}
}
