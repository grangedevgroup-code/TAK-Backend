package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/pkg/plugin"
)

func main() {
	p, err := plugin.Load()
	if err != nil {
		log.Fatal(err)
	}
	message := p.Setting("message", "Welcome to "+p.ServerName+", %s.")
	if !strings.Contains(message, "%s") {
		message += " %s"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	welcomed := map[string]bool{}
	p.Log.Printf("welcoming new devices with %q", message)
	p.Events(ctx, false, func(e plugin.Event) {
		if !e.IsDevice() || e.Callsign == "" || welcomed[e.UID] {
			return
		}
		welcomed[e.UID] = true
		if err := p.Chat(ctx, e.Callsign, fmt.Sprintf(message, e.Callsign)); err != nil {
			p.Log.Printf("could not welcome %s: %v", e.Callsign, err)
			return
		}
		p.Log.Printf("welcomed %s", e.Callsign)
	})
}
