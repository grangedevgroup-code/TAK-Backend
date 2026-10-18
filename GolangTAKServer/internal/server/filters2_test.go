package server

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestMessageFilterRulesAndImages(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.Filters.DropRules = []DropRule{{Type: "a-u-G", Threshold: 1}, {Type: "b-m-p*", Detail: "secret"}}
		c.Filters.Images = ImageFilters{Thumbnail: true, ThumbnailPixels: 16, URLAdd: true}
		c.Filters.Scrubber = true
	})
	rx := dialTCP(t, s)
	tx := dialTCP(t, s)
	rx.send(saXML("RXF", "RXF", 1, 1))
	u1 := cot.New("U-1", "a-u-G", "m-g", time.Minute)
	u2 := cot.New("U-2", "a-u-G", "m-g", time.Minute)
	tx.send(u1.String())
	rx.expect(uidIs("U-1"), "first unknown under the threshold")
	tx.send(u2.String())
	rx.expectNone(uidIs("U-2"), "second unknown over the per-minute threshold", 500*time.Millisecond)
	p := cot.New("P-1", "b-m-p-s-p-i", "h-e", time.Minute)
	p.Detail.AddNew("secret")
	tx.send(p.String())
	rx.expectNone(uidIs("P-1"), "point with the blocked detail", 500*time.Millisecond)
	bad := strings.Replace(cot.New("BAD-1", "a-f-G", "m-g", time.Minute).String(), `lat="0.0"`, `lat="123.0"`, 1)
	tx.send(bad)
	rx.expectNone(uidIs("BAD-1"), "out of range latitude scrubbed", 500*time.Millisecond)
	img := image.NewRGBA(image.Rect(0, 0, 200, 100))
	for x := 0; x < 200; x++ {
		for y := 0; y < 100; y++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 50, 255})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	pic := cot.New("PIC-1", "b-i-x-i", "h-e", time.Minute)
	pic.Detail.AddNew("image").Text = base64.StdEncoding.EncodeToString(buf.Bytes())
	tx.send(pic.String())
	got := rx.expect(uidIs("PIC-1"), "image event")
	n := got.D("image")
	if n == nil || n.Attr("url") == "" || n.Attr("thumburl") == "" {
		t.Fatalf("image not processed: %v", got.XML())
	}
	data, _ := base64.StdEncoding.DecodeString(n.Text)
	th, _, err := image.Decode(bytes.NewReader(data))
	if err != nil || th.Bounds().Dx() > 16 || th.Bounds().Dy() > 16 {
		t.Fatalf("thumbnail not reduced: %v %v", err, th)
	}
}
