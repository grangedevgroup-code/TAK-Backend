package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/aws"
)

type CloudWatchConfig struct {
	Enabled         bool   `json:"enabled"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name,omitempty"`
	Region          string `json:"region,omitempty"`
	BatchSize       int    `json:"batchSize,omitempty"`
	StepSeconds     int    `json:"stepSeconds,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

type cloudWatch struct {
	mu       sync.Mutex
	provider *aws.Provider
	static   aws.Credentials
	region   string
	last     map[string]float64
	client   *http.Client
	lastPush time.Time
	lastErr  string
	sent     int
}

func (c CloudWatchConfig) step() time.Duration {
	if c.StepSeconds > 0 {
		return time.Duration(c.StepSeconds) * time.Second
	}
	return time.Minute
}

func cloudWatchUnit(name, kind string) string {
	switch {
	case strings.HasSuffix(name, "_bytes"):
		return "Bytes"
	case strings.HasSuffix(name, "_seconds") || strings.HasSuffix(name, "_seconds_total"):
		return "Seconds"
	case kind == "counter":
		return "Count"
	}
	return "None"
}

func (s *Server) runCloudWatch(ctx context.Context) {
	cw := &cloudWatch{last: map[string]float64{}, client: &http.Client{Timeout: 20 * time.Second}}
	s.cw.Store(cw)
	timer := time.NewTimer(s.Config().Metrics.CloudWatch.step())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		cfg := s.Config().Metrics.CloudWatch
		timer.Reset(cfg.step())
		if !cfg.Enabled {
			continue
		}
		err := cw.push(ctx, s, cfg)
		cw.mu.Lock()
		prev := cw.lastErr
		if err != nil {
			cw.lastErr = err.Error()
			if prev != cw.lastErr {
				s.log.Warn("CloudWatch metrics could not be sent", "err", err)
			}
		} else {
			cw.lastErr = ""
			cw.lastPush = time.Now()
			if prev != "" {
				s.log.Info("CloudWatch metrics are being sent again")
			}
		}
		cw.mu.Unlock()
	}
}

func (cw *cloudWatch) credentials(ctx context.Context, cfg CloudWatchConfig) (aws.Credentials, string, error) {
	cw.mu.Lock()
	static := aws.Credentials{AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey}
	if cw.provider == nil || cw.static != static {
		cw.provider, cw.static, cw.region = aws.NewProvider(static), static, ""
	}
	p := cw.provider
	region := firstNonEmpty(cfg.Region, cw.region)
	cw.mu.Unlock()
	if region == "" {
		region = p.Region(ctx)
		cw.mu.Lock()
		cw.region = region
		cw.mu.Unlock()
	}
	if region == "" {
		return aws.Credentials{}, "", errors.New("set the AWS region")
	}
	creds, err := p.Get(ctx)
	return creds, region, err
}

type cwDatum struct {
	name   string
	unit   string
	value  float64
	labels []string
}

func (cw *cloudWatch) data(samples []metricSample) []cwDatum {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	var out []cwDatum
	for _, m := range samples {
		if strings.HasSuffix(m.name, "_info") {
			continue
		}
		v := m.value
		if m.kind == "counter" {
			key := m.name + "\x00" + strings.Join(m.labels, "\x00")
			prev, seen := cw.last[key]
			cw.last[key] = m.value
			if !seen {
				continue
			}
			v = m.value - prev
			if v < 0 {
				v = m.value
			}
		}
		out = append(out, cwDatum{name: m.name, unit: cloudWatchUnit(m.name, m.kind), value: v, labels: m.labels})
	}
	return out
}

func (cw *cloudWatch) push(ctx context.Context, s *Server, cfg CloudWatchConfig) error {
	data := cw.data(s.collectMetrics().samples)
	if len(data) == 0 {
		return nil
	}
	creds, region, err := cw.credentials(ctx, cfg)
	if err != nil {
		return err
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://monitoring." + region + ".amazonaws.com/"
	}
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 20
	}
	batch = min(batch, 1000)
	now := time.Now().UTC()
	for i := 0; i < len(data); i += batch {
		form := url.Values{"Action": {"PutMetricData"}, "Version": {"2010-08-01"}, "Namespace": {firstNonEmpty(cfg.Namespace, "takserver")}}
		for j, d := range data[i:min(i+batch, len(data))] {
			pre := "MetricData.member." + strconv.Itoa(j+1) + "."
			form.Set(pre+"MetricName", d.name)
			form.Set(pre+"Value", strconv.FormatFloat(d.value, 'f', -1, 64))
			form.Set(pre+"Unit", d.unit)
			form.Set(pre+"Timestamp", now.Format(time.RFC3339))
			n := 0
			if cfg.Name != "" {
				n++
				form.Set(pre+"Dimensions.member."+strconv.Itoa(n)+".Name", "Name")
				form.Set(pre+"Dimensions.member."+strconv.Itoa(n)+".Value", cfg.Name)
			}
			for k := 0; k+1 < len(d.labels) && n < 30; k += 2 {
				n++
				form.Set(pre+"Dimensions.member."+strconv.Itoa(n)+".Name", d.labels[k])
				form.Set(pre+"Dimensions.member."+strconv.Itoa(n)+".Value", firstNonEmpty(d.labels[k+1], "-"))
			}
		}
		body := []byte(form.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		aws.Sign(req, body, creds, region, "monitoring", now)
		resp, err := cw.client.Do(req)
		if err != nil {
			return err
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("CloudWatch answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
		}
	}
	cw.mu.Lock()
	cw.sent += len(data)
	cw.mu.Unlock()
	return nil
}

func (s *Server) apiCloudWatchStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config().Metrics.CloudWatch
	out := map[string]any{"enabled": cfg.Enabled, "namespace": firstNonEmpty(cfg.Namespace, "takserver")}
	if cw := s.cw.Load(); cw != nil {
		cw.mu.Lock()
		out["region"], out["lastError"], out["metricsSent"] = firstNonEmpty(cfg.Region, cw.region), cw.lastErr, cw.sent
		if !cw.lastPush.IsZero() {
			out["lastPush"] = cw.lastPush.UTC().Format(time.RFC3339)
		}
		cw.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, out)
}
