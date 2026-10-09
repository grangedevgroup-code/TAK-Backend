package xmltree

import (
	"strings"
	"testing"
)

func TestParseEvent(t *testing.T) {
	in := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!-- comment -->
<event version="2.0" uid="ANDROID-1" type='a-f-G-U-C' how="m-g">
  <point lat="40.1" lon="-105.2" hae="1600" ce="5" le="5"/>
  <detail>
    <contact callsign="Alpha &amp; Co" endpoint="*:-1:stcp"/>
    <remarks>line one
line &lt;two&gt; <![CDATA[<raw & stuff>]]></remarks>
    <__group name="Cyan" role="Team Member"></__group>
  </detail>
</event>`
	n, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if n.Name != "event" || n.Attr("uid") != "ANDROID-1" || n.Attr("type") != "a-f-G-U-C" {
		t.Fatalf("bad root: %+v", n)
	}
	if got := n.Find("detail", "contact").Attr("callsign"); got != "Alpha & Co" {
		t.Fatalf("callsign %q", got)
	}
	rem := n.Find("detail", "remarks").Text
	if rem != "line one\nline <two> <raw & stuff>" {
		t.Fatalf("remarks %q", rem)
	}
	if n.Find("detail").Text != "" {
		t.Fatalf("whitespace kept as text: %q", n.Find("detail").Text)
	}
	if g := n.Find("detail", "__group"); g == nil || !g.Leaf() {
		t.Fatal("group not parsed as leaf")
	}
	out := n.String()
	again, err := Parse([]byte(out))
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, out)
	}
	if again.String() != out {
		t.Fatalf("not stable:\n%s\n%s", out, again.String())
	}
	if !strings.Contains(out, `callsign="Alpha &amp; Co"`) || !strings.Contains(out, "line &lt;two&gt; &lt;raw &amp; stuff&gt;") {
		t.Fatalf("escaping wrong: %s", out)
	}
}

func TestErrors(t *testing.T) {
	cases := []string{
		``,
		`   `,
		`<event`,
		`<event uid="x"`,
		`<event uid="x">`,
		`<event><detail></event>`,
		`<event uid=x/>`,
		`<event uid="x"/`,
		`<>`,
		`<a><!DOCTYPE x></a>`,
		`<a><![CDATA[x</a>`,
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	s := strings.Repeat("<a>", MaxDepth+2) + strings.Repeat("</a>", MaxDepth+2)
	if _, err := Parse([]byte(s)); err != ErrDepth {
		t.Fatalf("want depth error, got %v", err)
	}
	ok := strings.Repeat("<a>", MaxDepth) + strings.Repeat("</a>", MaxDepth)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxDepth, err)
	}
}

func TestEntitiesAndEscaping(t *testing.T) {
	n, err := Parse([]byte(`<a v="&#65;&#x42;&quot;&apos;&unknown;&amp"/>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Attr("v"); got != `AB"'&unknown;&amp` {
		t.Fatalf("attr %q", got)
	}
	m := New("x", "a", "tab\there\nnl\r\"q\" <&>", "b", "bad\x01ctl")
	m.Text = "text\x02 with \r and \t\n"
	s := m.String()
	want := `<x a="tab&#9;here&#10;nl&#13;&quot;q&quot; &lt;&amp;&gt;" b="badctl">text with &#13; and ` + "\t\n" + `</x>`
	if s != want {
		t.Fatalf("got  %s\nwant %s", s, want)
	}
	back, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	if back.Attr("a") != "tab\there\nnl\r\"q\" <&>" {
		t.Fatalf("roundtrip attr %q", back.Attr("a"))
	}
	if back.Text != "text with \r and \t\n" {
		t.Fatalf("roundtrip text %q", back.Text)
	}
	inv := New("y", "a", "x\xffy")
	if got := inv.String(); got != "<y a=\"x�y\"/>" {
		t.Fatalf("invalid utf8: %q", got)
	}
}

func TestFragment(t *testing.T) {
	nodes, err := ParseFragment([]byte(`<a x="1"/> junk <b><c/></b><!-- c --><d>t</d>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 || nodes[0].Name != "a" || nodes[1].Child("c") == nil || nodes[2].Text != "t" {
		t.Fatalf("fragment: %v", nodes)
	}
}

func TestEditing(t *testing.T) {
	n := New("detail")
	n.AddNew("contact", "callsign", "A")
	n.AddNew("marti").AddNew("dest", "callsign", "B")
	n.AddNew("link", "uid", "1")
	n.AddNew("link", "uid", "2")
	if len(n.All("link")) != 2 {
		t.Fatal("All")
	}
	if n.RemoveAll("link") != 2 || len(n.Children) != 2 {
		t.Fatal("RemoveAll")
	}
	c := n.Clone()
	c.Child("contact").SetAttr("callsign", "Z")
	if n.Child("contact").Attr("callsign") != "A" {
		t.Fatal("clone shares state")
	}
	c.Child("contact").RemoveAttr("callsign")
	if c.Child("contact").HasAttr("callsign") {
		t.Fatal("RemoveAttr")
	}
	if !n.Remove(n.Child("marti")) || n.Child("marti") != nil {
		t.Fatal("Remove")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`<event uid="a"><point lat="1"/><detail><x y="z">t</x></detail></event>`))
	f.Add([]byte(`<a><![CDATA[x]]><!-- y --><?pi?></a>`))
	f.Add([]byte(`<a b='&#x41;&lt;'>&amp;</a>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		n, err := Parse(data)
		if err != nil {
			return
		}
		out := n.String()
		again, err := Parse([]byte(out))
		if err != nil {
			t.Fatalf("serialized output does not parse: %v\n%q", err, out)
		}
		if again.String() != out {
			t.Fatalf("unstable:\n%q\n%q", out, again.String())
		}
	})
}
