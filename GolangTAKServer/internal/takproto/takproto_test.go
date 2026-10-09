package takproto

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

const sa = `<event version="2.0" uid="ANDROID-abc" type="a-f-G-U-C" how="m-g" time="2026-01-02T03:04:05.123Z" start="2026-01-02T03:04:05.123Z" stale="2026-01-02T03:10:05.123Z" access="Undefined"><point lat="40.123456" lon="-105.654321" hae="1600.5" ce="9999999.0" le="9999999.0"/><detail><takv os="34" version="5.4.0.16" device="PIXEL" platform="ATAK-CIV"/><contact endpoint="*:-1:stcp" callsign="ALPHA"/><uid Droid="ALPHA"/><precisionlocation altsrc="GPS" geopointsrc="GPS"/><__group role="Team Member" name="Cyan"/><status battery="88"/><track course="123.4" speed="1.5"/></detail></event>`

func TestRoundTrip(t *testing.T) {
	e, err := cot.Parse([]byte(sa))
	if err != nil {
		t.Fatal(err)
	}
	b := Marshal(e)
	m, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	g := m.Event
	if g.UID != e.UID || g.Type != e.Type || g.How != e.How || g.Access != "Undefined" {
		t.Fatalf("header: %+v", g)
	}
	if !g.Time.Equal(e.Time) || !g.Stale.Equal(e.Stale) {
		t.Fatalf("times %v %v", g.Time, g.Stale)
	}
	if g.Point != e.Point {
		t.Fatalf("point %+v vs %+v", g.Point, e.Point)
	}
	if g.Callsign() != "ALPHA" || g.Endpoint() != "*:-1:stcp" {
		t.Fatal("contact")
	}
	if n, r := g.Team(); n != "Cyan" || r != "Team Member" {
		t.Fatal("group")
	}
	if g.D("status").Attr("battery") != "88" || g.D("track").Attr("speed") != "1.5" || g.D("track").Attr("course") != "123.4" {
		t.Fatalf("status/track: %s", g)
	}
	if g.D("uid").Attr("Droid") != "ALPHA" {
		t.Fatal("xmlDetail lost")
	}
	if _, p, o, v := g.Takv(); p != "ATAK-CIV" || o != "34" || v != "5.4.0.16" {
		t.Fatal("takv")
	}
	if !bytes.Contains(b, []byte(`<uid Droid="ALPHA"/>`)) || bytes.Contains(b, []byte("<contact")) {
		t.Fatalf("typed fields not extracted: %q", b)
	}
}

func TestNonConformingStaysXML(t *testing.T) {
	e, _ := cot.Parse([]byte(`<event uid="u" type="a-f-G"><detail><contact callsign="A" phone="123"/><status battery="88" readiness="true"/><track speed="x" course="1"/><takv platform="WinTAK"/></detail></event>`))
	b := Marshal(e)
	for _, want := range []string{`phone="123"`, `readiness="true"`, `speed="x"`, `platform="WinTAK"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("%s should stay in xmlDetail", want)
		}
	}
	g, err := UnmarshalEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.D("contact").Attr("phone") != "123" || g.D("takv").Attr("platform") != "WinTAK" {
		t.Fatalf("lost data: %s", g)
	}
}

func TestXMLDetailOverridesTyped(t *testing.T) {
	var d []byte
	d = appendBytes(d, 1, []byte(`<contact callsign="FROMXML"/>`))
	var c []byte
	c = appendString(c, 2, "FROMPROTO")
	d = appendBytes(d, 2, c)
	var ev []byte
	ev = appendString(ev, 1, "a-f-G")
	ev = appendString(ev, 5, "x")
	ev = appendBytes(ev, 15, d)
	g, err := UnmarshalEvent(appendBytes(nil, 2, ev))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Detail.All("contact")) != 1 || g.Callsign() != "FROMXML" {
		t.Fatalf("override rule: %s", g)
	}
	if g.Stale.IsZero() || g.Time.IsZero() {
		t.Fatal("times not normalized")
	}
}

func TestControl(t *testing.T) {
	m, err := Unmarshal(MarshalControl(Control{MinVersion: 1, MaxVersion: 1, ContactUID: "x"}))
	if err != nil || m.Control == nil || m.Control.MaxVersion != 1 || m.Control.ContactUID != "x" || m.Event != nil {
		t.Fatalf("control %+v %v", m, err)
	}
	if _, err := UnmarshalEvent(MarshalControl(Control{})); err != ErrNoEvent {
		t.Fatal("expected ErrNoEvent")
	}
}

func TestBadInput(t *testing.T) {
	bad := [][]byte{
		{0x12},
		{0x12, 0x05, 0x01},
		{0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		{0x0b},
		{0x00},
	}
	for _, b := range bad {
		if _, err := Unmarshal(b); err == nil {
			t.Errorf("accepted %x", b)
		}
	}
}

func TestMesh(t *testing.T) {
	e, _ := cot.Parse([]byte(sa))
	frame := MeshFrame(Marshal(e))
	payload, ok := ParseMesh(frame)
	if !ok {
		t.Fatal("mesh header")
	}
	g, err := UnmarshalEvent(payload)
	if err != nil || g.UID != e.UID {
		t.Fatal(err)
	}
	if _, ok := ParseMesh([]byte{0xbf, 0x01}); ok {
		t.Fatal("short mesh accepted")
	}
}

func TestReaderMixedStream(t *testing.T) {
	e, _ := cot.Parse([]byte(sa))
	var stream bytes.Buffer
	stream.WriteString("\n<?xml version=\"1.0\"?>\n")
	stream.WriteString(`<event uid="a" type="t-x-c-t"><detail><x note="a > b"/><![CDATA[</event>]]></detail></event>`)
	stream.WriteString("  junk  ")
	stream.WriteString(`<auth><cot username="u" password="p&gt;" uid="ANDROID-1"/></auth>`)
	stream.WriteString(`<event uid="self" type="t-x-c-t"/>`)
	stream.Write(AppendStreamFrame(nil, Marshal(e)))
	stream.WriteString("<!-- trailing --><event uid=\"z\" type=\"a\"><detail/></event>")
	for _, rd := range []io.Reader{bytes.NewReader(stream.Bytes()), iotest.OneByteReader(bytes.NewReader(stream.Bytes())), iotest.HalfReader(bytes.NewReader(stream.Bytes()))} {
		r := NewReader(rd, 1<<20)
		var frames []Frame
		for {
			f, err := r.Next()
			if err != nil {
				if err != io.EOF {
					t.Fatal(err)
				}
				break
			}
			frames = append(frames, f)
		}
		if len(frames) != 5 {
			t.Fatalf("got %d frames: %+v", len(frames), frames)
		}
		if !strings.Contains(string(frames[0].Data), "<![CDATA[</event>]]></detail></event>") {
			t.Fatalf("cdata frame: %s", frames[0].Data)
		}
		if !strings.HasPrefix(string(frames[1].Data), "<auth>") || string(frames[2].Data) != `<event uid="self" type="t-x-c-t"/>` {
			t.Fatalf("frames: %q %q", frames[1].Data, frames[2].Data)
		}
		if !frames[3].Proto {
			t.Fatal("proto frame not detected")
		}
		g, err := UnmarshalEvent(frames[3].Data)
		if err != nil || g.Callsign() != "ALPHA" {
			t.Fatal("proto frame decode")
		}
		if _, err := cot.Parse(frames[4].Data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReaderLimit(t *testing.T) {
	big := "<event uid=\"a\" type=\"b\"><detail>" + strings.Repeat("x", 5000) + "</detail></event>"
	r := NewReader(strings.NewReader(big), 1000)
	if _, err := r.Next(); err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge got %v", err)
	}
	r = NewReader(bytes.NewReader(AppendStreamFrame(nil, make([]byte, 2000))), 1000)
	if _, err := r.Next(); err != ErrTooLarge {
		t.Fatalf("proto: want ErrTooLarge got %v", err)
	}
	ok := NewReader(strings.NewReader(big), 6000)
	if f, err := ok.Next(); err != nil || len(f.Data) != len(big) {
		t.Fatalf("within limit: %v", err)
	}
}

func BenchmarkMarshal(b *testing.B) {
	e, _ := cot.Parse([]byte(sa))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Marshal(e)
	}
}

func BenchmarkParseXML(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cot.Parse([]byte(sa))
	}
}

func FuzzUnmarshal(f *testing.F) {
	e, _ := cot.Parse([]byte(sa))
	f.Add(Marshal(e))
	f.Add(MarshalControl(Control{MinVersion: 1}))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Unmarshal(data)
		if err != nil || m.Event == nil {
			return
		}
		again, err := UnmarshalEvent(Marshal(m.Event))
		if err != nil {
			t.Fatalf("re-marshal failed: %v", err)
		}
		if again.UID != m.Event.UID || again.Type != m.Event.Type {
			t.Fatal("identity changed")
		}
		_ = again.String()
		_ = time.Now()
	})
}

func FuzzReader(f *testing.F) {
	f.Add([]byte(`<event uid="a" type="b"/><auth><cot/></auth>`))
	f.Add(AppendStreamFrame([]byte("<?xml?>"), []byte{0x12, 0x00}))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bytes.NewReader(data), 4096)
		total := 0
		for i := 0; i < 10000; i++ {
			fr, err := r.Next()
			if err != nil {
				return
			}
			total += len(fr.Data)
			if total > len(data) {
				t.Fatal("produced more data than input")
			}
		}
		t.Fatal("reader did not terminate")
	})
}
