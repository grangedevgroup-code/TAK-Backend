package xmltree

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrSyntax   = errors.New("xml: syntax error")
	ErrEOF      = errors.New("xml: unexpected end of input")
	ErrDepth    = errors.New("xml: nesting too deep")
	ErrMismatch = errors.New("xml: mismatched end tag")
	ErrNoRoot   = errors.New("xml: no root element")
)

const MaxDepth = 128

type Attr struct {
	Name  string
	Value string
}

type Node struct {
	Name     string
	Attrs    []Attr
	Children []*Node
	Text     string
}

func New(name string, attrs ...string) *Node {
	n := &Node{Name: name}
	for i := 0; i+1 < len(attrs); i += 2 {
		n.Attrs = append(n.Attrs, Attr{Name: attrs[i], Value: attrs[i+1]})
	}
	return n
}

func (n *Node) Attr(name string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

func (n *Node) HasAttr(name string) bool {
	if n == nil {
		return false
	}
	for _, a := range n.Attrs {
		if a.Name == name {
			return true
		}
	}
	return false
}

func (n *Node) SetAttr(name, value string) *Node {
	for i := range n.Attrs {
		if n.Attrs[i].Name == name {
			n.Attrs[i].Value = value
			return n
		}
	}
	n.Attrs = append(n.Attrs, Attr{Name: name, Value: value})
	return n
}

func (n *Node) RemoveAttr(name string) {
	out := n.Attrs[:0]
	for _, a := range n.Attrs {
		if a.Name != name {
			out = append(out, a)
		}
	}
	n.Attrs = out
}

func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (n *Node) All(name string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, c := range n.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func (n *Node) Find(path ...string) *Node {
	cur := n
	for _, p := range path {
		cur = cur.Child(p)
		if cur == nil {
			return nil
		}
	}
	return cur
}

func (n *Node) Add(c *Node) *Node {
	n.Children = append(n.Children, c)
	return c
}

func (n *Node) AddNew(name string, attrs ...string) *Node {
	return n.Add(New(name, attrs...))
}

func (n *Node) Remove(c *Node) bool {
	for i, x := range n.Children {
		if x == c {
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return true
		}
	}
	return false
}

func (n *Node) RemoveAll(name string) int {
	out := n.Children[:0]
	removed := 0
	for _, c := range n.Children {
		if c.Name == name {
			removed++
			continue
		}
		out = append(out, c)
	}
	for i := len(out); i < len(n.Children); i++ {
		n.Children[i] = nil
	}
	n.Children = out
	return removed
}

func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	c := &Node{Name: n.Name, Text: n.Text}
	if len(n.Attrs) > 0 {
		c.Attrs = append([]Attr(nil), n.Attrs...)
	}
	if len(n.Children) > 0 {
		c.Children = make([]*Node, len(n.Children))
		for i, ch := range n.Children {
			c.Children[i] = ch.Clone()
		}
	}
	return c
}

func (n *Node) Walk(fn func(*Node) bool) {
	if n == nil || !fn(n) {
		return
	}
	for _, c := range n.Children {
		c.Walk(fn)
	}
}

func (n *Node) Leaf() bool {
	return len(n.Children) == 0 && n.Text == ""
}

func (n *Node) String() string {
	return string(n.AppendXML(nil))
}

func (n *Node) AppendXML(dst []byte) []byte {
	dst = append(dst, '<')
	dst = append(dst, n.Name...)
	for _, a := range n.Attrs {
		dst = append(dst, ' ')
		dst = append(dst, a.Name...)
		dst = append(dst, '=', '"')
		dst = EscapeAttr(dst, a.Value)
		dst = append(dst, '"')
	}
	mark := len(dst)
	dst = append(dst, '>')
	if n.Text != "" {
		dst = EscapeText(dst, n.Text)
	}
	if len(n.Children) == 0 && len(dst) == mark+1 {
		dst = dst[:mark]
		return append(dst, '/', '>')
	}
	for _, c := range n.Children {
		dst = c.AppendXML(dst)
	}
	dst = append(dst, '<', '/')
	dst = append(dst, n.Name...)
	return append(dst, '>')
}

func AppendChildren(dst []byte, n *Node) []byte {
	if n == nil {
		return dst
	}
	if n.Text != "" {
		dst = EscapeText(dst, n.Text)
	}
	for _, c := range n.Children {
		dst = c.AppendXML(dst)
	}
	return dst
}

func validXMLRune(r rune) bool {
	return r == 0x09 || r == 0x0A || r == 0x0D ||
		(r >= 0x20 && r <= 0xD7FF) ||
		(r >= 0xE000 && r <= 0xFFFD) ||
		(r >= 0x10000 && r <= 0x10FFFF)
}

func escape(dst []byte, s string, attr bool) []byte {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	last := 0
	for i := 0; i < len(s); {
		c := s[i]
		var rep string
		width := 1
		if c < utf8.RuneSelf {
			switch c {
			case '&':
				rep = "&amp;"
			case '<':
				rep = "&lt;"
			case '>':
				rep = "&gt;"
			case '"':
				if attr {
					rep = "&quot;"
				}
			case '\n':
				if attr {
					rep = "&#10;"
				}
			case '\r':
				rep = "&#13;"
			case '\t':
				if attr {
					rep = "&#9;"
				}
			default:
				if c < 0x20 {
					rep = "\x00"
				}
			}
		} else {
			r, w := utf8.DecodeRuneInString(s[i:])
			width = w
			if !validXMLRune(r) {
				rep = "\x00"
			}
		}
		if rep == "" {
			i += width
			continue
		}
		dst = append(dst, s[last:i]...)
		if rep != "\x00" {
			dst = append(dst, rep...)
		}
		i += width
		last = i
	}
	return append(dst, s[last:]...)
}

func Sanitize(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if validXMLRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func EscapeAttr(dst []byte, s string) []byte { return escape(dst, s, true) }

func EscapeText(dst []byte, s string) []byte { return escape(dst, s, false) }

func EscapeString(s string) string { return string(escape(nil, s, true)) }

type parser struct {
	data  []byte
	pos   int
	depth int
}

func Parse(data []byte) (*Node, error) {
	p := &parser{data: data}
	if err := p.skipMisc(); err != nil {
		return nil, err
	}
	if p.pos >= len(p.data) {
		return nil, ErrNoRoot
	}
	if p.data[p.pos] != '<' {
		return nil, ErrSyntax
	}
	return p.element()
}

func ParseFragment(data []byte) ([]*Node, error) {
	p := &parser{data: data}
	var out []*Node
	for {
		if err := p.skipMisc(); err != nil {
			return out, err
		}
		if p.pos >= len(p.data) {
			return out, nil
		}
		if p.data[p.pos] != '<' {
			j := bytes.IndexByte(p.data[p.pos:], '<')
			if j < 0 {
				return out, nil
			}
			p.pos += j
			continue
		}
		n, err := p.element()
		if err != nil {
			return out, err
		}
		out = append(out, n)
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isNameByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '/', '>', '<', '=', '"', '\'', 0:
		return false
	}
	return true
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) && isSpace(p.data[p.pos]) {
		p.pos++
	}
}

func (p *parser) has(prefix string) bool {
	return len(p.data)-p.pos >= len(prefix) && string(p.data[p.pos:p.pos+len(prefix)]) == prefix
}

func (p *parser) skipPast(term string) error {
	j := bytes.Index(p.data[p.pos:], []byte(term))
	if j < 0 {
		return ErrEOF
	}
	p.pos += j + len(term)
	return nil
}

func (p *parser) skipDoctype() error {
	depth := 0
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		p.pos++
		switch c {
		case '[':
			depth++
		case ']':
			depth--
		case '>':
			if depth <= 0 {
				return nil
			}
		}
	}
	return ErrEOF
}

func (p *parser) skipMisc() error {
	for {
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil
		}
		if p.data[p.pos] == 0xEF && p.has("\xEF\xBB\xBF") {
			p.pos += 3
			continue
		}
		switch {
		case p.has("<?"):
			if err := p.skipPast("?>"); err != nil {
				return err
			}
		case p.has("<!--"):
			if err := p.skipPast("-->"); err != nil {
				return err
			}
		case p.has("<!"):
			if err := p.skipDoctype(); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (p *parser) name() string {
	start := p.pos
	for p.pos < len(p.data) && isNameByte(p.data[p.pos]) {
		p.pos++
	}
	return string(p.data[start:p.pos])
}

func (p *parser) element() (*Node, error) {
	p.pos++
	name := p.name()
	if name == "" {
		return nil, ErrSyntax
	}
	n := &Node{Name: name}
	for {
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, ErrEOF
		}
		c := p.data[p.pos]
		if c == '/' {
			if p.pos+1 >= len(p.data) {
				return nil, ErrEOF
			}
			if p.data[p.pos+1] != '>' {
				return nil, ErrSyntax
			}
			p.pos += 2
			return n, nil
		}
		if c == '>' {
			p.pos++
			break
		}
		an := p.name()
		if an == "" {
			return nil, ErrSyntax
		}
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, ErrEOF
		}
		if p.data[p.pos] != '=' {
			return nil, ErrSyntax
		}
		p.pos++
		p.skipSpace()
		if p.pos >= len(p.data) {
			return nil, ErrEOF
		}
		q := p.data[p.pos]
		if q != '"' && q != '\'' {
			return nil, ErrSyntax
		}
		p.pos++
		end := bytes.IndexByte(p.data[p.pos:], q)
		if end < 0 {
			return nil, ErrEOF
		}
		n.Attrs = append(n.Attrs, Attr{Name: an, Value: Sanitize(Unescape(p.data[p.pos : p.pos+end]))})
		p.pos += end + 1
	}
	p.depth++
	if p.depth > MaxDepth {
		return nil, ErrDepth
	}
	var text []byte
	for {
		if p.pos >= len(p.data) {
			return nil, ErrEOF
		}
		if p.data[p.pos] != '<' {
			j := bytes.IndexByte(p.data[p.pos:], '<')
			if j < 0 {
				return nil, ErrEOF
			}
			text = appendUnescaped(text, p.data[p.pos:p.pos+j])
			p.pos += j
			continue
		}
		switch {
		case p.has("</"):
			p.pos += 2
			end := p.name()
			if end != name {
				return nil, ErrMismatch
			}
			p.skipSpace()
			if p.pos >= len(p.data) {
				return nil, ErrEOF
			}
			if p.data[p.pos] != '>' {
				return nil, ErrSyntax
			}
			p.pos++
			p.depth--
			s := Sanitize(string(text))
			if len(n.Children) > 0 {
				if strings.TrimSpace(s) != "" {
					n.Text = s
				}
			} else {
				n.Text = s
			}
			return n, nil
		case p.has("<!--"):
			if err := p.skipPast("-->"); err != nil {
				return nil, err
			}
		case p.has("<![CDATA["):
			p.pos += 9
			j := bytes.Index(p.data[p.pos:], []byte("]]>"))
			if j < 0 {
				return nil, ErrEOF
			}
			text = append(text, p.data[p.pos:p.pos+j]...)
			p.pos += j + 3
		case p.has("<?"):
			if err := p.skipPast("?>"); err != nil {
				return nil, err
			}
		case p.has("<!"):
			return nil, ErrSyntax
		default:
			child, err := p.element()
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
		}
	}
}

func Unescape(b []byte) string {
	if bytes.IndexByte(b, '&') < 0 {
		return string(b)
	}
	return string(appendUnescaped(nil, b))
}

func appendUnescaped(dst, b []byte) []byte {
	for {
		i := bytes.IndexByte(b, '&')
		if i < 0 {
			return append(dst, b...)
		}
		dst = append(dst, b[:i]...)
		b = b[i:]
		semi := bytes.IndexByte(b, ';')
		if semi < 0 || semi > 12 {
			dst = append(dst, '&')
			b = b[1:]
			continue
		}
		ent := string(b[1:semi])
		switch ent {
		case "lt":
			dst = append(dst, '<')
		case "gt":
			dst = append(dst, '>')
		case "amp":
			dst = append(dst, '&')
		case "quot":
			dst = append(dst, '"')
		case "apos":
			dst = append(dst, '\'')
		default:
			r, ok := charRef(ent)
			if !ok {
				dst = append(dst, b[:semi+1]...)
				b = b[semi+1:]
				continue
			}
			dst = utf8.AppendRune(dst, r)
		}
		b = b[semi+1:]
	}
}

func charRef(ent string) (rune, bool) {
	if len(ent) < 2 || ent[0] != '#' {
		return 0, false
	}
	var v uint64
	var err error
	if ent[1] == 'x' || ent[1] == 'X' {
		v, err = strconv.ParseUint(ent[2:], 16, 32)
	} else {
		v, err = strconv.ParseUint(ent[1:], 10, 32)
	}
	if err != nil || v > utf8.MaxRune {
		return 0, false
	}
	return rune(v), true
}
