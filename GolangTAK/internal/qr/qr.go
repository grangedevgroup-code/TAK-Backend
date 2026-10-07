package qr

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
)

type Level int

const (
	L Level = iota
	M
	Q
	H
)

var ErrTooLong = errors.New("qr: data too long")

var eccCodewordsPerBlock = [4][41]int{
	{-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	{-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
}

var numErrorCorrectionBlocks = [4][41]int{
	{-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	{-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	{-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	{-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
}

var formatBitsFor = [4]int{1, 0, 3, 2}

type Code struct {
	Size     int
	Version  int
	Level    Level
	Mask     int
	modules  []bool
	function []bool
}

func (c *Code) Black(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.modules[y*c.Size+x]
}

func (c *Code) set(x, y int, dark bool) {
	c.modules[y*c.Size+x] = dark
	c.function[y*c.Size+x] = true
}

func rawDataModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		n := ver/7 + 2
		r -= (25*n-10)*n - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}

func dataCodewords(ver int, l Level) int {
	return rawDataModules(ver)/8 - eccCodewordsPerBlock[l][ver]*numErrorCorrectionBlocks[l][ver]
}

func countBits(ver int) int {
	if ver <= 9 {
		return 8
	}
	return 16
}

func Encode(text string, level Level) (*Code, error) {
	return EncodeBytes([]byte(text), level)
}

func EncodeBytes(data []byte, level Level) (*Code, error) {
	ver := 0
	for v := 1; v <= 40; v++ {
		if 4+countBits(v)+8*len(data) <= dataCodewords(v, level)*8 {
			ver = v
			break
		}
	}
	if ver == 0 || len(data) >= 1<<16 {
		return nil, ErrTooLong
	}
	used := 4 + countBits(ver) + 8*len(data)
	for l := level + 1; l <= H; l++ {
		if used <= dataCodewords(ver, l)*8 {
			level = l
		}
	}
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, (v>>uint(i))&1 == 1)
		}
	}
	put(4, 4)
	put(len(data), countBits(ver))
	for _, b := range data {
		put(int(b), 8)
	}
	capacity := dataCodewords(ver, level) * 8
	term := capacity - len(bits)
	if term > 4 {
		term = 4
	}
	put(0, term)
	put(0, (8-len(bits)%8)%8)
	for pad := 0xEC; len(bits) < capacity; pad ^= 0xEC ^ 0x11 {
		put(pad, 8)
	}
	codewords := make([]byte, len(bits)/8)
	for i, b := range bits {
		if b {
			codewords[i>>3] |= 1 << uint(7-i&7)
		}
	}
	c := &Code{Size: ver*4 + 17, Version: ver, Level: level}
	c.modules = make([]bool, c.Size*c.Size)
	c.function = make([]bool, c.Size*c.Size)
	c.drawFunctionPatterns()
	c.drawCodewords(c.addECC(codewords))
	best, bestPenalty := 0, -1
	for m := 0; m < 8; m++ {
		c.applyMask(m)
		c.drawFormatBits(m)
		p := c.penalty()
		if bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = m, p
		}
		c.applyMask(m)
	}
	c.Mask = best
	c.applyMask(best)
	c.drawFormatBits(best)
	return c, nil
}

func (c *Code) drawFunctionPatterns() {
	for i := 0; i < c.Size; i++ {
		c.set(6, i, i%2 == 0)
		c.set(i, 6, i%2 == 0)
	}
	c.drawFinder(3, 3)
	c.drawFinder(c.Size-4, 3)
	c.drawFinder(3, c.Size-4)
	pos := alignmentPositions(c.Version, c.Size)
	n := len(pos)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			c.drawAlignment(pos[i], pos[j])
		}
	}
	c.drawFormatBits(0)
	c.drawVersion()
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (c *Code) drawFinder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			d := max(abs(dx), abs(dy))
			xx, yy := x+dx, y+dy
			if xx >= 0 && xx < c.Size && yy >= 0 && yy < c.Size {
				c.set(xx, yy, d != 2 && d != 4)
			}
		}
	}
}

func (c *Code) drawAlignment(x, y int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			c.set(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
		}
	}
}

func alignmentPositions(ver, size int) []int {
	if ver == 1 {
		return nil
	}
	n := ver/7 + 2
	step := (ver*8 + n*3 + 5) / (n*4 - 4) * 2
	out := make([]int, n)
	out[0] = 6
	for i, p := n-1, size-7; i >= 1; i, p = i-1, p-step {
		out[i] = p
	}
	return out
}

func bit(v, i int) bool { return (v>>uint(i))&1 != 0 }

func (c *Code) drawFormatBits(mask int) {
	data := formatBitsFor[c.Level]<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	bits := (data<<10 | rem) ^ 0x5412
	for i := 0; i <= 5; i++ {
		c.set(8, i, bit(bits, i))
	}
	c.set(8, 7, bit(bits, 6))
	c.set(8, 8, bit(bits, 7))
	c.set(7, 8, bit(bits, 8))
	for i := 9; i < 15; i++ {
		c.set(14-i, 8, bit(bits, i))
	}
	for i := 0; i < 8; i++ {
		c.set(c.Size-1-i, 8, bit(bits, i))
	}
	for i := 8; i < 15; i++ {
		c.set(8, c.Size-15+i, bit(bits, i))
	}
	c.set(8, c.Size-8, true)
}

func (c *Code) drawVersion() {
	if c.Version < 7 {
		return
	}
	rem := c.Version
	for i := 0; i < 12; i++ {
		rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
	}
	bits := c.Version<<12 | rem
	for i := 0; i < 18; i++ {
		b := bit(bits, i)
		a := c.Size - 11 + i%3
		d := i / 3
		c.set(a, d, b)
		c.set(d, a, b)
	}
}

func gfMul(x, y byte) byte {
	z := 0
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= int((y>>uint(i))&1) * int(x)
	}
	return byte(z)
}

func rsDivisor(degree int) []byte {
	res := make([]byte, degree)
	res[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := range res {
			res[j] = gfMul(res[j], root)
			if j+1 < len(res) {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return res
}

func rsRemainder(data, divisor []byte) []byte {
	res := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(divisor[i], factor)
		}
	}
	return res
}

func (c *Code) addECC(data []byte) []byte {
	numBlocks := numErrorCorrectionBlocks[c.Level][c.Version]
	eccLen := eccCodewordsPerBlock[c.Level][c.Version]
	raw := rawDataModules(c.Version) / 8
	numShort := numBlocks - raw%numBlocks
	shortLen := raw / numBlocks
	div := rsDivisor(eccLen)
	blocks := make([][]byte, numBlocks)
	k := 0
	for i := 0; i < numBlocks; i++ {
		n := shortLen - eccLen
		if i >= numShort {
			n++
		}
		dat := append([]byte(nil), data[k:k+n]...)
		k += n
		ecc := rsRemainder(dat, div)
		if i < numShort {
			dat = append(dat, 0)
		}
		blocks[i] = append(dat, ecc...)
	}
	out := make([]byte, 0, raw)
	for i := range blocks[0] {
		for j, b := range blocks {
			if i != shortLen-eccLen || j >= numShort {
				out = append(out, b[i])
			}
		}
	}
	return out
}

func (c *Code) drawCodewords(data []byte) {
	i := 0
	total := len(data) * 8
	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < c.Size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				up := (right+1)&2 == 0
				y := vert
				if up {
					y = c.Size - 1 - vert
				}
				idx := y*c.Size + x
				if !c.function[idx] && i < total {
					c.modules[idx] = (data[i>>3]>>uint(7-i&7))&1 != 0
					i++
				}
			}
		}
	}
}

func maskBit(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (c *Code) applyMask(m int) {
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			idx := y*c.Size + x
			if !c.function[idx] && maskBit(m, x, y) {
				c.modules[idx] = !c.modules[idx]
			}
		}
	}
}

func (c *Code) penalty() int {
	const n1, n2, n3, n4 = 3, 3, 40, 10
	res := 0
	size := c.Size
	line := func(get func(i int) bool) {
		runColor := false
		run := 0
		var hist [7]int
		for i := 0; i < size; i++ {
			if get(i) == runColor {
				run++
				if run == 5 {
					res += n1
				} else if run > 5 {
					res++
				}
			} else {
				c.addHistory(run, &hist)
				if !runColor {
					res += countPatterns(&hist) * n3
				}
				runColor = get(i)
				run = 1
			}
		}
		if runColor {
			c.addHistory(run, &hist)
			run = 0
		}
		run += size
		c.addHistory(run, &hist)
		res += countPatterns(&hist) * n3
	}
	for y := 0; y < size; y++ {
		line(func(i int) bool { return c.modules[y*size+i] })
	}
	for x := 0; x < size; x++ {
		line(func(i int) bool { return c.modules[i*size+x] })
	}
	for y := 0; y < size-1; y++ {
		for x := 0; x < size-1; x++ {
			col := c.modules[y*size+x]
			if col == c.modules[y*size+x+1] && col == c.modules[(y+1)*size+x] && col == c.modules[(y+1)*size+x+1] {
				res += n2
			}
		}
	}
	dark := 0
	for _, m := range c.modules {
		if m {
			dark++
		}
	}
	total := size * size
	k := (abs(dark*20-total*10)+total-1)/total - 1
	return res + k*n4
}

func (c *Code) addHistory(run int, hist *[7]int) {
	if hist[0] == 0 {
		run += c.Size
	}
	copy(hist[1:], hist[:6])
	hist[0] = run
}

func countPatterns(h *[7]int) int {
	n := h[1]
	core := n > 0 && h[2] == n && h[3] == n*3 && h[4] == n && h[5] == n
	r := 0
	if core && h[0] >= n*4 && h[6] >= n {
		r++
	}
	if core && h[6] >= n*4 && h[0] >= n {
		r++
	}
	return r
}

func (c *Code) SVG(scale, border int) string {
	if scale < 1 {
		scale = 1
	}
	dim := (c.Size + 2*border) * scale
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges">`, c.Size+2*border, c.Size+2*border, dim, dim)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d,%dh1v1h-1z", x+border, y+border)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

func (c *Code) Image(scale, border int) image.Image {
	if scale < 1 {
		scale = 1
	}
	dim := (c.Size + 2*border) * scale
	img := image.NewPaletted(image.Rect(0, 0, dim, dim), color.Palette{color.White, color.Black})
	for y := 0; y < dim; y++ {
		for x := 0; x < dim; x++ {
			if c.Black(x/scale-border, y/scale-border) {
				img.SetColorIndex(x, y, 1)
			}
		}
	}
	return img
}

func (c *Code) PNG(scale, border int) []byte {
	var buf bytes.Buffer
	png.Encode(&buf, c.Image(scale, border))
	return buf.Bytes()
}

func (c *Code) Terminal(border int, indent string) string {
	var b strings.Builder
	for y := -border; y < c.Size+border; y += 2 {
		b.WriteString(indent)
		for x := -border; x < c.Size+border; x++ {
			top, bottom := c.Black(x, y), c.Black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString(" ")
			case top:
				b.WriteString("▄")
			case bottom:
				b.WriteString("▀")
			default:
				b.WriteString("█")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (c *Code) TerminalANSI(border int, indent string) string {
	var b strings.Builder
	for y := -border; y < c.Size+border; y += 2 {
		b.WriteString(indent)
		b.WriteString("\x1b[30;107m")
		for x := -border; x < c.Size+border; x++ {
			top, bottom := c.Black(x, y), c.Black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String()
}

func (c *Code) ASCII(border int, indent string) string {
	var b strings.Builder
	for y := -border; y < c.Size+border; y++ {
		b.WriteString(indent)
		for x := -border; x < c.Size+border; x++ {
			if c.Black(x, y) {
				b.WriteString("##")
			} else {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
