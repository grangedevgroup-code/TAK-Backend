package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/websocket"
)

type event struct {
	UID      string `json:"uid"`
	Type     string `json:"type"`
	Callsign string `json:"callsign"`
}

func main() {
	base := os.Getenv("GOLANGTAK_URL")
	stream := os.Getenv("GOLANGTAK_STREAM_URL")
	token := os.Getenv("GOLANGTAK_TOKEN")
	if base == "" || token == "" {
		log.Fatal("run this as a GolangTAK server plugin: golangtak plugin add welcome /path/to/welcome")
	}
	message := os.Getenv("WELCOME_MESSAGE")
	if message == "" {
		message = "Welcome to " + os.Getenv("GOLANGTAK_SERVER_NAME") + ", %s."
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pem, err := os.ReadFile(os.Getenv("GOLANGTAK_CA")); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.RootCAs = pool
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	welcomed := map[string]bool{}
	for {
		err := listen(stream, token, tlsCfg, func(e event) {
			if !strings.HasPrefix(e.Type, "a-f-") || e.Callsign == "" || welcomed[e.UID] {
				return
			}
			welcomed[e.UID] = true
			if err := sendChat(hc, base, token, e.Callsign, fmt.Sprintf(message, e.Callsign)); err != nil {
				log.Printf("could not welcome %s: %v", e.Callsign, err)
				return
			}
			log.Printf("welcomed %s", e.Callsign)
		})
		log.Printf("event stream closed (%v); reconnecting in 5 seconds", err)
		time.Sleep(5 * time.Second)
	}
}

func listen(url, token string, tlsCfg *tls.Config, handle func(event)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{TLS: tlsCfg, Header: http.Header{"Authorization": {"Bearer " + token}}})
	cancel()
	if err != nil {
		return err
	}
	defer conn.CloseNow()
	log.Printf("listening to %s", url)
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var e event
		if json.Unmarshal(data, &e) == nil {
			handle(e)
		}
	}
}

func sendChat(hc *http.Client, base, token, to, text string) error {
	body, _ := json.Marshal(map[string]string{"message": text, "to": to, "sender": "Server"})
	req, err := http.NewRequest(http.MethodPost, base+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
