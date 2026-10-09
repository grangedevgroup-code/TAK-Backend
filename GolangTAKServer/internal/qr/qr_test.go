package qr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var samples = []string{
	"HELLO",
	"tak://com.atakmap.app/enroll?host=tak.example.com&username=alice&token=abcd-efgh-jkmn",
	"GolangTAKServer,192.168.1.10,8089,SSL",
	strings.Repeat("0123456789abcdef", 40),
	"",
	"éè unicode 中文",
}

func TestStructure(t *testing.T) {
	for _, s := range samples {
		for l := L; l <= H; l++ {
			c, err := Encode(s, l)
			if err != nil {
				t.Fatal(err)
			}
			if c.Size != c.Version*4+17 {
				t.Fatal("size")
			}
			for _, p := range [][2]int{{0, 0}, {c.Size - 7, 0}, {0, c.Size - 7}} {
				for i := 0; i < 7; i++ {
					if !c.Black(p[0]+i, p[1]) || !c.Black(p[0], p[1]+i) || !c.Black(p[0]+3, p[1]+3) {
						t.Fatalf("finder pattern broken at %v", p)
					}
				}
			}
			if !c.Black(8, c.Size-8) {
				t.Fatal("dark module")
			}
			if c.Level < l {
				t.Fatal("level lowered")
			}
		}
	}
	if _, err := Encode(strings.Repeat("x", 3000), H); err != ErrTooLong {
		t.Fatal("expected ErrTooLong")
	}
	big, err := Encode(strings.Repeat("x", 2900), L)
	if err != nil || big.Version != 40 {
		t.Fatalf("v40: %v %v", err, big)
	}
}

func TestAlignment(t *testing.T) {
	want := map[int][]int{2: {6, 18}, 7: {6, 22, 38}, 14: {6, 26, 46, 66}, 32: {6, 34, 60, 86, 112, 138}, 40: {6, 30, 58, 86, 114, 142, 170}}
	for v, w := range want {
		got := alignmentPositions(v, v*4+17)
		if fmt.Sprint(got) != fmt.Sprint(w) {
			t.Errorf("v%d: %v want %v", v, got, w)
		}
	}
}

func TestRenderers(t *testing.T) {
	c, _ := Encode("test", M)
	if !strings.HasPrefix(c.SVG(4, 4), "<svg") || len(c.PNG(4, 4)) < 100 || !strings.Contains(c.Terminal(2, ""), "█") || !strings.Contains(c.ASCII(1, ""), "##") {
		t.Fatal("renderers")
	}
}

func TestDump(t *testing.T) {
	dir := os.Getenv("QR_DUMP_DIR")
	if dir == "" {
		t.Skip("set QR_DUMP_DIR to export codes for external verification")
	}
	os.MkdirAll(dir, 0o755)
	n := 0
	for _, s := range samples {
		for l := L; l <= H; l++ {
			c, _ := Encode(s, l)
			var b strings.Builder
			fmt.Fprintf(&b, "%d %d %d\n", c.Version, int(c.Level), c.Mask)
			for y := 0; y < c.Size; y++ {
				for x := 0; x < c.Size; x++ {
					if c.Black(x, y) {
						b.WriteByte('1')
					} else {
						b.WriteByte('0')
					}
				}
				b.WriteByte('\n')
			}
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.txt", n)), []byte(b.String()), 0o644)
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.png", n)), c.PNG(6, 4), 0o644)
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.data", n)), []byte(s), 0o644)
			n++
		}
	}
}
