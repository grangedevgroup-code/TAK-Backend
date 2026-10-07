package meshtastic

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math"
	"testing"
)

func TestDefaultChannel(t *testing.T) {
	key, err := ParseKey("AQ==")
	if err != nil || !bytes.Equal(key, DefaultKey) {
		t.Fatalf("default key %x %v", key, err)
	}
	if h := ChannelHash("LongFast", key); h != 8 {
		t.Fatalf("LongFast channel hash %d, want 8", h)
	}
	k2, _ := ParseKey("Ag==")
	if k2[15] != DefaultKey[15]+1 || !bytes.Equal(k2[:15], DefaultKey[:15]) {
		t.Fatalf("key index 2: %x", k2)
	}
	if k, _ := ParseKey("AA=="); k != nil {
		t.Fatal("key 0 should disable encryption")
	}
	if k, _ := ParseKey("none"); k != nil {
		t.Fatal("none should disable encryption")
	}
	if k, err := ParseKey("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="); err != nil || len(k) != 32 {
		t.Fatalf("aes-256 key: %d %v", len(k), err)
	}
	if _, err := ParseKey("!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
}

func TestCryptNonceLayout(t *testing.T) {
	plain := []byte("hello mesh, this is longer than one block of sixteen bytes")
	enc, err := Crypt(DefaultKey, 0x01020304, 0xaabbccdd, plain)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(DefaultKey)
	nonce := []byte{0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0, 0xdd, 0xcc, 0xbb, 0xaa, 0, 0, 0, 0}
	want := make([]byte, len(plain))
	cipher.NewCTR(block, nonce).XORKeyStream(want, plain)
	if !bytes.Equal(enc, want) {
		t.Fatal("nonce layout differs from packet id (8 bytes LE) + sender (4 bytes LE) + 4 zero bytes")
	}
	dec, _ := Crypt(DefaultKey, 0x01020304, 0xaabbccdd, enc)
	if !bytes.Equal(dec, plain) {
		t.Fatal("round trip failed")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	pos := &Position{LatI: 388977000, LonI: -770365000, Altitude: -12, GroundSpeed: 3, GroundTrack: 9000000, HasTrack: true}
	data := &Data{Portnum: PortPosition, Payload: pos.Marshal()}
	enc, _ := Crypt(DefaultKey, 42, 0x11223344, data.Marshal())
	env := &Envelope{Packet: &Packet{From: 0x11223344, To: Broadcast, Channel: 8, ID: 42, HopLimit: 3, HopStart: 3, Encrypted: enc}, ChannelID: "LongFast", GatewayID: "!11223344"}
	got, err := ParseEnvelope(env.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.ChannelID != "LongFast" || got.GatewayID != "!11223344" || got.Packet.From != 0x11223344 || got.Packet.To != Broadcast || got.Packet.ID != 42 || got.Packet.Channel != 8 {
		t.Fatalf("%+v %+v", got, got.Packet)
	}
	plain, _ := Crypt(DefaultKey, got.Packet.ID, got.Packet.From, got.Packet.Encrypted)
	d, err := ParseData(plain)
	if err != nil || d.Portnum != PortPosition {
		t.Fatalf("data %+v %v", d, err)
	}
	p, err := ParsePosition(d.Payload)
	if err != nil || !p.HasPosition || p.Altitude != -12 || math.Abs(p.Lat()-38.8977) > 1e-9 || math.Abs(p.Lon()+77.0365) > 1e-9 {
		t.Fatalf("position %+v %v", p, err)
	}
	if c, ok := p.Course(); !ok || c != 90 {
		t.Fatalf("course %v", c)
	}
	p.GroundTrack = 4500
	if c, _ := p.Course(); c != 45 {
		t.Fatalf("course in hundredths %v", c)
	}
	if _, err := ParseEnvelope([]byte{0x0a, 0x05, 0x01}); err == nil {
		t.Fatal("truncated envelope accepted")
	}
}

func TestTAKPacketAndUser(t *testing.T) {
	in := &TAKPacket{Callsign: "ALPHA-1", DeviceCallsign: "ANDROID-1", Role: RoleNumber("Team Lead"), Team: TeamNumber("Dark Blue"), Battery: 77,
		PLI: &PLI{LatI: 100, LonI: -200, Altitude: 30, Speed: 2, Course: 180}}
	out, err := ParseTAK(in.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if out.Callsign != "ALPHA-1" || out.DeviceCallsign != "ANDROID-1" || RoleName(out.Role) != "Team Lead" || TeamName(out.Team) != "Dark Blue" || out.Battery != 77 || out.PLI == nil || out.PLI.LonI != -200 || out.PLI.Course != 180 {
		t.Fatalf("%+v %+v", out, out.PLI)
	}
	chat := &TAKPacket{Callsign: "B", Chat: &GeoChat{Message: "hi", To: "All Chat Rooms"}}
	c, _ := ParseTAK(chat.Marshal())
	if c.Chat == nil || c.Chat.Message != "hi" || c.Chat.To != "All Chat Rooms" {
		t.Fatalf("%+v", c)
	}
	u := &User{ID: "!aabbccdd", LongName: "Base Camp", ShortName: "BC", HWModel: 43}
	pu, _ := ParseUser(u.Marshal())
	if *pu != *u {
		t.Fatalf("%+v", pu)
	}
	if n, ok := ParseNodeID("!AABBCCDD"); !ok || n != 0xaabbccdd || NodeID(n) != "!aabbccdd" {
		t.Fatal("node id")
	}
	if _, ok := ParseNodeID("!xyz"); ok {
		t.Fatal("bad node id accepted")
	}
	tel := putBytes(putFixed32(nil, 1, 1), 2, putVarint(nil, 1, 88))
	dm, err := ParseDeviceMetrics(tel)
	if err != nil || dm == nil || !dm.HasBattery || dm.Battery != 88 {
		t.Fatalf("telemetry %+v %v", dm, err)
	}
}
