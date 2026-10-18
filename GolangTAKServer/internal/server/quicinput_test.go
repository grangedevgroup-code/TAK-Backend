package server

import (
	"context"
	"crypto/tls"
	"strconv"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/quic"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/takproto"
)

func TestQUICInputDeliversWithCertIdentity(t *testing.T) {
	port := freeUDPPort(t)
	s := newTestServer(t, func(c *Config) {
		c.AllowAnonymous = false
		c.Inputs = []InputConfig{{Name: "stdquic", Protocol: "quic", Port: port, QUICTimeout: 20}}
	})
	s.dir.EnsureGroup("Red", "", false)
	s.dir.EnsureGroup("Blue", "", false)
	s.dir.AddUser("red1", "password1", false, []string{"Red"})
	s.dir.AddUser("red2", "password2", false, []string{"Red"})
	s.dir.AddUser("blue1", "password3", false, []string{"Blue"})
	certFor := func(user string) tls.Certificate {
		certPEM, keyPEM, cert, err := s.pki.NewClientPEM(user, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		s.dir.RecordCert(user, CertRecord{Serial: pki.SerialHex(cert), Created: time.Now()})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	r1c, r2c, b1c := certFor("red1"), certFor("red2"), certFor("blue1")
	r2, err := dialTLS(t, s, &r2c)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := dialTLS(t, s, &b1c)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qs, err := quic.Dial(ctx, "127.0.0.1:"+strconv.Itoa(port), &tls.Config{RootCAs: s.pki.ClientPool(), ServerName: "127.0.0.1", Certificates: []tls.Certificate{r1c}}, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { qs.Close() })
	defer func() {
		if t.Failed() {
			dumpLogs(t, s)
		}
	}()
	q := &testClient{t: t, conn: qs, r: takproto.NewReader(qs, 1<<22)}
	q.send(saXML("Q1", "QUIC1", 1, 1))
	r2.expect(uidIs("Q1"), "quic client to same group")
	b1.expectNone(uidIs("Q1"), "quic cross-group leak", 500*time.Millisecond)
	r2.send(saXML("R2", "RED2", 1, 1))
	q.expect(uidIs("R2"), "same group to quic client")
	found := false
	for _, c := range s.hub.Clients() {
		if c.Kind == KindQUIC && c.User() == "red1" {
			found = true
		}
	}
	if !found {
		t.Fatal("quic client not registered as red1")
	}
	var metrics []map[string]any
	for _, m := range s.inputMetrics(true) {
		if m["id"] == "stdquic" {
			metrics = append(metrics, m)
		}
	}
	if len(metrics) != 1 || metrics[0]["numClients"].(int64) != 1 {
		t.Fatalf("input metrics %v", metrics)
	}
	if in := metrics[0]["input"].(map[string]any); in["protocol"] != "quic" || in["auth"] != "X509" || in["quicConnectionTimeoutSeconds"] != 20 {
		t.Fatalf("input json %v", in)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if nc, err := quic.Dial(ctx2, "127.0.0.1:"+strconv.Itoa(port), &tls.Config{RootCAs: s.pki.ClientPool(), ServerName: "127.0.0.1"}, 5*time.Second); err == nil {
		nc.Write([]byte(saXML("NOCERT", "NOCERT", 1, 1)))
		r2.expectNone(uidIs("NOCERT"), "quic client without certificate", 700*time.Millisecond)
		nc.Close()
	}
}

func TestQUICInputValidation(t *testing.T) {
	if err := validateInput(InputConfig{Name: "q", Protocol: "quic", Port: 8090}); err != nil {
		t.Fatal(err)
	}
	if a := (InputConfig{Protocol: "quic"}).auth(); a != "x509" {
		t.Fatalf("default auth %q", a)
	}
	var in InputConfig
	takInputBody{Name: "q", Protocol: "QUIC", Port: 8090, QUICTimeout: 45}.apply(&in)
	if in.Protocol != "quic" || in.QUICTimeout != 45 {
		t.Fatalf("%+v", in)
	}
}
