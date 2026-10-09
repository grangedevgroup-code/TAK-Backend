package server

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/meshtastic"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/mqtt"
)

func meshPublish(t *testing.T, c *mqtt.Client, from, id uint32, port uint32, payload []byte) {
	t.Helper()
	d := &meshtastic.Data{Portnum: port, Payload: payload}
	enc, err := meshtastic.Crypt(meshtastic.DefaultKey, id, from, d.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	env := &meshtastic.Envelope{Packet: &meshtastic.Packet{From: from, To: meshtastic.Broadcast, ID: id, Channel: 8, HopLimit: 3, Encrypted: enc}, ChannelID: "LongFast", GatewayID: meshtastic.NodeID(from)}
	if err := c.Publish("msh/US/2/e/LongFast/"+meshtastic.NodeID(from), env.Marshal()); err != nil {
		t.Fatal(err)
	}
}

func TestMeshtasticBridge(t *testing.T) {
	port := freePort(t)
	s := newTestServer(t, func(c *Config) {
		c.Meshtastic = MeshtasticConfig{Enabled: true, BrokerPort: port, BrokerAnonymous: true, Root: "msh/US", Downlink: true, IntervalSec: 10,
			Channels: []MeshtasticChannel{{Name: "LongFast", Key: "AQ=="}}}
	})
	gw, err := mqtt.Dial(context.Background(), "mqtt://127.0.0.1:"+strconv.Itoa(port), mqtt.ClientOptions{ClientID: "!0a0b0c0d"})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	if err := gw.Subscribe("msh/US/2/e/LongFast/+"); err != nil {
		t.Fatal(err)
	}
	tak := dialTCP(t, s)
	const node = 0x0a0b0c0d
	user := meshtastic.User{ID: meshtastic.NodeID(node), LongName: "Ridge Relay", ShortName: "RR"}
	meshPublish(t, gw, node, 1001, meshtastic.PortNodeInfo, user.Marshal())
	pos := meshtastic.Position{LatI: 389000000, LonI: -770100000, Altitude: 120, GroundSpeed: 2, GroundTrack: 9000000}
	meshPublish(t, gw, node, 1002, meshtastic.PortPosition, pos.Marshal())
	meshPublish(t, gw, node, 1002, meshtastic.PortPosition, pos.Marshal())
	e := tak.expect(uidIs("MESHTASTIC-!0a0b0c0d"), "mesh node position")
	if e.Callsign() != "Ridge Relay" || e.Point.Lat < 38.89 || e.Point.Lat > 38.91 || e.Point.Hae != 120 {
		t.Fatalf("mesh SA %s", e)
	}
	meshPublish(t, gw, node, 1003, meshtastic.PortText, []byte("hello from mesh"))
	chat := tak.expect(func(e *cot.Event) bool { return e.IsChat() }, "mesh chat")
	if chat.Remarks() != "hello from mesh" || !strings.Contains(chat.String(), `senderCallsign="Ridge Relay"`) {
		t.Fatalf("chat %s", chat)
	}

	tak.send(saXML("ANDROID-tak1", "TAK-ONE", 38.91, -77.02))
	tak.send(cot.Chat("ANDROID-tak1", "TAK-ONE", "All Chat Rooms", "All Chat Rooms", "copy, from TAK", nil).String())
	gotPLI, gotText := false, false
	deadline := time.After(10 * time.Second)
	for !(gotPLI && gotText) {
		select {
		case m := <-gw.Messages():
			env, err := meshtastic.ParseEnvelope(m.Payload)
			if err != nil {
				t.Fatalf("downlink envelope: %v", err)
			}
			if env.ChannelID != "LongFast" || env.Packet.Channel != 8 || env.Packet.To != meshtastic.Broadcast || !strings.HasSuffix(m.Topic, env.GatewayID) {
				t.Fatalf("downlink envelope %+v %+v", env, env.Packet)
			}
			plain, _ := meshtastic.Crypt(meshtastic.DefaultKey, env.Packet.ID, env.Packet.From, env.Packet.Encrypted)
			d, err := meshtastic.ParseData(plain)
			if err != nil {
				t.Fatalf("downlink data: %v", err)
			}
			switch d.Portnum {
			case meshtastic.PortATAK:
				tp, err := meshtastic.ParseTAK(d.Payload)
				if err != nil || tp.PLI == nil {
					t.Fatalf("TAK packet %+v %v", tp, err)
				}
				if tp.Callsign != "TAK-ONE" || tp.DeviceCallsign != "ANDROID-tak1" || tp.Battery != 90 || meshtastic.TeamName(tp.Team) != "Cyan" {
					t.Fatalf("TAK packet %+v", tp)
				}
				gotPLI = true
			case meshtastic.PortText:
				if string(d.Payload) != "TAK-ONE: copy, from TAK" {
					t.Fatalf("text %q", d.Payload)
				}
				gotText = true
			}
		case <-deadline:
			t.Fatalf("downlink incomplete: position %v text %v", gotPLI, gotText)
		}
	}
	tak.expectNone(func(e *cot.Event) bool {
		return e.Remarks() == "copy, from TAK" && strings.Contains(e.UID, "MESHTASTIC")
	}, "chat echoed back from the mesh", 500*time.Millisecond)

	for _, c := range s.hub.Clients() {
		if c.Kind == KindMeshtastic && (!c.Relay || !c.Internal()) {
			t.Fatal("the Meshtastic bridge must be a built-in relay client")
		}
	}
	if owner := s.hub.ByUID("MESHTASTIC-!0a0b0c0d"); owner == nil || owner.Kind != KindMeshtastic || !owner.Relay {
		t.Fatalf("mesh node uid must route through the bridge, got %v", owner)
	}
	st := s.meshStatus()
	if !st.Enabled || st.BrokerClients != 1 || st.PacketsIn != 3 || st.PacketsOut < 2 || len(st.Nodes) != 1 || st.Nodes[0].Name != "Ridge Relay" {
		t.Fatalf("status %+v", st)
	}

	other, _ := meshtastic.ParseKey("Ag==")
	d := &meshtastic.Data{Portnum: meshtastic.PortText, Payload: []byte("secret channel")}
	enc, _ := meshtastic.Crypt(other, 5000, node, d.Marshal())
	env := &meshtastic.Envelope{Packet: &meshtastic.Packet{From: node, To: meshtastic.Broadcast, ID: 5000, Channel: 99, Encrypted: enc}, ChannelID: "Private", GatewayID: "!0a0b0c0d"}
	gw.Publish("msh/US/2/e/Private/!0a0b0c0d", env.Marshal())
	tak.expectNone(func(e *cot.Event) bool { return e.Remarks() == "secret channel" }, "message from an unknown channel key", 700*time.Millisecond)
	if s.meshStatus().Undecryptable == 0 {
		t.Fatal("undecryptable packet not counted")
	}
}

func TestMeshtasticBrokerRequiresAccount(t *testing.T) {
	port := freePort(t)
	s := newTestServer(t, func(c *Config) {
		c.Meshtastic = MeshtasticConfig{Enabled: true, BrokerPort: port, Root: "msh/US", Channels: []MeshtasticChannel{{Name: "LongFast", Key: "AQ=="}}}
	})
	if _, err := s.dir.AddUser("meshnode", "mesh-password", false, nil); err != nil {
		t.Fatal(err)
	}
	url := "mqtt://127.0.0.1:" + strconv.Itoa(port)
	if _, err := mqtt.Dial(context.Background(), url, mqtt.ClientOptions{ClientID: "x"}); err == nil {
		t.Fatal("anonymous MQTT client accepted")
	}
	c, err := mqtt.Dial(context.Background(), url, mqtt.ClientOptions{ClientID: "y", Username: "meshnode", Password: "mesh-password"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
