package klv

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func Sample(lat, lon float64) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC).UnixMicro()))
	return Encode([]Item{
		{2, ts},
		{3, []byte("MISSION 7")},
		{5, EncodeU(90, 0, 360, 2)},
		{6, EncodeS(-5, 40, 2)},
		{10, []byte("RAVEN 1")},
		{11, []byte("EO")},
		{13, EncodeS(lat, 180, 4)},
		{14, EncodeS(lon, 360, 4)},
		{15, EncodeU(350, -900, 19000, 2)},
		{16, EncodeU(30, 0, 180, 2)},
		{17, EncodeU(20, 0, 180, 2)},
		{18, EncodeU(45, 0, 360, 4)},
		{19, EncodeS(-30, 360, 4)},
		{21, EncodeU(800, 0, 5000000, 4)},
		{23, EncodeS(lat+0.005, 180, 4)},
		{24, EncodeS(lon+0.005, 360, 4)},
		{25, EncodeU(10, -900, 19000, 2)},
		{26, EncodeS(0.001, 0.15, 2)}, {27, EncodeS(-0.001, 0.15, 2)},
		{28, EncodeS(0.001, 0.15, 2)}, {29, EncodeS(0.001, 0.15, 2)},
		{30, EncodeS(-0.001, 0.15, 2)}, {31, EncodeS(0.001, 0.15, 2)},
		{32, EncodeS(-0.001, 0.15, 2)}, {33, EncodeS(-0.001, 0.15, 2)},
		{56, []byte{25}},
	})
}

func TestParseUAS(t *testing.T) {
	pkt := Sample(38.8895, -77.0353)
	u, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !u.HasSensor || !near(u.SensorLat, 38.8895, 1e-6) || !near(u.SensorLon, -77.0353, 1e-6) {
		t.Fatalf("sensor %v %v %v", u.HasSensor, u.SensorLat, u.SensorLon)
	}
	if !near(u.Heading, 90, 0.01) || !near(u.Pitch, -5, 0.01) || !near(u.SensorAlt, 350, 0.5) || !near(u.HFOV, 30, 0.01) || !near(u.VFOV, 20, 0.01) {
		t.Fatalf("attitude %+v", u)
	}
	if !near(u.SensorAzimuth(), 135, 0.01) || !near(u.SensorRelElev, -30, 0.01) || !near(u.SlantRange, 800, 1) {
		t.Fatalf("sensor pointing %v %v %v", u.SensorAzimuth(), u.SensorRelElev, u.SlantRange)
	}
	if !u.HasFrame || !near(u.FrameLat, 38.8945, 1e-6) || len(u.Corners) != 4 || !near(u.Corners[0].Lat, 38.8955, 1e-5) {
		t.Fatalf("frame %v %v %v", u.HasFrame, u.FrameLat, u.Corners)
	}
	if u.Name() != "RAVEN 1" || u.SensorName != "EO" || u.GroundSpeed != 25 || u.Time.Year() != 2026 {
		t.Fatalf("names %q %q %v %v", u.Name(), u.SensorName, u.GroundSpeed, u.Time)
	}
}

func TestChecksumAndSearch(t *testing.T) {
	pkt := Sample(10, 20)
	bad := append([]byte(nil), pkt...)
	bad[30] ^= 0xff
	if _, err := Parse(bad); err != ErrChecksum {
		t.Fatalf("corrupted packet: %v", err)
	}
	stream := append(append(append([]byte{0, 1, 2, 3, 4}, pkt...), 9, 9), Sample(11, 21)...)
	found := FindAll(stream)
	if len(found) != 2 {
		t.Fatalf("found %d packets", len(found))
	}
	u, err := Parse(found[1])
	if err != nil || !near(u.SensorLat, 11, 1e-6) {
		t.Fatalf("second packet: %v %v", u, err)
	}
	if _, err := Parse(pkt[:20]); err == nil {
		t.Fatal("truncated packet accepted")
	}
}
