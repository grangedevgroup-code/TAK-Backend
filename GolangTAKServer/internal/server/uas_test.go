package server

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/klv"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/media"
)

func uasKLV(lat, lon float64) []byte {
	return klv.Encode([]klv.Item{
		{Tag: 5, Value: klv.EncodeU(270, 0, 360, 2)},
		{Tag: 10, Value: []byte("RAVEN 7")},
		{Tag: 13, Value: klv.EncodeS(lat, 180, 4)},
		{Tag: 14, Value: klv.EncodeS(lon, 360, 4)},
		{Tag: 15, Value: klv.EncodeU(400, -900, 19000, 2)},
		{Tag: 16, Value: klv.EncodeU(25, 0, 180, 2)},
		{Tag: 17, Value: klv.EncodeU(15, 0, 180, 2)},
		{Tag: 18, Value: klv.EncodeU(10, 0, 360, 4)},
		{Tag: 23, Value: klv.EncodeS(lat+0.01, 180, 4)},
		{Tag: 24, Value: klv.EncodeS(lon-0.01, 360, 4)},
	})
}

func TestDroneVideoWithTelemetry(t *testing.T) {
	rtspPort := freePort(t)
	udpPort := freePort(t)
	s := newTestServer(t, func(c *Config) {
		c.Video = VideoServerConfig{Enabled: true, RTSPPort: rtspPort, AnonymousRead: true, Sources: []VideoSource{
			{Name: "drone", URL: "udp://127.0.0.1:" + strconv.Itoa(udpPort), Path: "uas/raven", Enabled: true},
		}}
	})
	rx := dialTCP(t, s)
	rx.send(saXML("uas-watcher", "WATCH", 1, 1))

	sps, _ := hex.DecodeString("6764001eacd940a02ff97011000003000100000300320f162d96")
	pps, _ := hex.DecodeString("68ebe3cb22c0")
	idr := append([]byte{0x65, 0x88}, make([]byte, 600)...)
	conn, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(udpPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	mux := media.NewTSMuxer()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		pts := int64(90000)
		for i := 0; ctx.Err() == nil; i++ {
			var b []byte
			if i%10 == 0 {
				b = append(b, mux.Tables()...)
			}
			b = append(b, mux.Video(pts, [][]byte{sps, pps, idr})...)
			b = append(b, mux.KLV(pts, uasKLV(34.05, -118.25))...)
			for len(b) > 0 {
				n := min(len(b), 7*188)
				conn.Write(b[:n])
				b = b[n:]
			}
			pts += 3000
			time.Sleep(40 * time.Millisecond)
		}
	}()

	p := rx.expect(func(e *cot.Event) bool { return e.UID == "uas-uas-raven" }, "drone marker")
	if p.Type != uasType || p.Point.Lat < 34.04 || p.Point.Lat > 34.06 || p.Point.Lon > -118.24 {
		t.Fatalf("drone at %v,%v type %s", p.Point.Lat, p.Point.Lon, p.Type)
	}
	if c := p.D("contact"); c == nil || c.Attr("callsign") != "RAVEN 7" {
		t.Fatal("callsign missing")
	}
	sn := p.D("sensor")
	if sn == nil || sn.Attr("fov") != "25.00" || sn.Attr("azimuth") != "280.0" {
		t.Fatalf("sensor detail %v", sn)
	}
	if v := p.D("__video"); v == nil || v.Attr("url") != "rtsp://127.0.0.1:"+strconv.Itoa(rtspPort)+"/uas/raven" {
		t.Fatal("video link missing")
	}
	spi := rx.expect(func(e *cot.Event) bool { return e.UID == "uas-uas-raven-spi" }, "sensor point of interest")
	if spi.Point.Lat < 34.059 || spi.Point.Lat > 34.061 {
		t.Fatalf("SPI at %v", spi.Point.Lat)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, ok := s.live.reg.Get("uas/raven"); ok {
			if len(st.Desc.Tracks) != 2 || st.Desc.Tracks[1].Codec != "SMPTE336M" {
				t.Fatalf("tracks %+v", st.Desc.Tracks)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("video was not republished")
		}
		time.Sleep(100 * time.Millisecond)
	}

	pl, err := media.Dial(context.Background(), "rtsp://127.0.0.1:"+strconv.Itoa(rtspPort)+"/uas/raven", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	desc, err := pl.Describe()
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.SetupPlay(desc); err != nil {
		t.Fatal(err)
	}
	got := map[int]bool{}
	pl.ReadPackets(3*time.Second, func(pk media.Packet) {
		if !pk.RTCP {
			got[pk.Track] = true
		}
		if got[0] && got[1] {
			pl.Close()
		}
	})
	if !got[0] || !got[1] {
		t.Fatalf("RTSP viewer received tracks %v", got)
	}
}
