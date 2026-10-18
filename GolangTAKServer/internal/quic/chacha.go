package quic

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

func chachaBlock(key *[8]uint32, counter uint32, nonce *[3]uint32, out *[64]byte) {
	var s, x [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	copy(s[4:12], key[:])
	s[12] = counter
	s[13], s[14], s[15] = nonce[0], nonce[1], nonce[2]
	x = s
	for i := 0; i < 10; i++ {
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}
	for i := range x {
		binary.LittleEndian.PutUint32(out[i*4:], x[i]+s[i])
	}
}

func chachaKey(k []byte) *[8]uint32 {
	var key [8]uint32
	for i := range key {
		key[i] = binary.LittleEndian.Uint32(k[i*4:])
	}
	return &key
}

func chachaNonce(n []byte) *[3]uint32 {
	return &[3]uint32{binary.LittleEndian.Uint32(n[0:]), binary.LittleEndian.Uint32(n[4:]), binary.LittleEndian.Uint32(n[8:])}
}

func chachaXOR(key []byte, counter uint32, nonce []byte, dst, src []byte) {
	k, n := chachaKey(key), chachaNonce(nonce)
	var block [64]byte
	for len(src) > 0 {
		chachaBlock(k, counter, n, &block)
		counter++
		m := min(len(src), 64)
		subtle.XORBytes(dst[:m], src[:m], block[:m])
		dst, src = dst[m:], src[m:]
	}
}

type poly1305 struct {
	r0, r1, r2, r3, r4 uint64
	h0, h1, h2, h3, h4 uint64
	s0, s1, s2, s3     uint64
}

func newPoly1305(key []byte) *poly1305 {
	p := &poly1305{}
	t0 := binary.LittleEndian.Uint32(key[0:])
	t1 := binary.LittleEndian.Uint32(key[3:])
	t2 := binary.LittleEndian.Uint32(key[6:])
	t3 := binary.LittleEndian.Uint32(key[9:])
	t4 := binary.LittleEndian.Uint32(key[12:])
	p.r0 = uint64(t0 & 0x3ffffff)
	p.r1 = uint64((t1 >> 2) & 0x3ffff03)
	p.r2 = uint64((t2 >> 4) & 0x3ffc0ff)
	p.r3 = uint64((t3 >> 6) & 0x3f03fff)
	p.r4 = uint64((t4 >> 8) & 0x00fffff)
	p.s0 = uint64(binary.LittleEndian.Uint32(key[16:]))
	p.s1 = uint64(binary.LittleEndian.Uint32(key[20:]))
	p.s2 = uint64(binary.LittleEndian.Uint32(key[24:]))
	p.s3 = uint64(binary.LittleEndian.Uint32(key[28:]))
	return p
}

func (p *poly1305) block(m []byte, final bool) {
	var buf [17]byte
	copy(buf[:], m)
	if final {
		buf[len(m)] = 1
	} else {
		buf[16] = 1
	}
	t0 := uint64(binary.LittleEndian.Uint32(buf[0:]))
	t1 := uint64(binary.LittleEndian.Uint32(buf[3:]))
	t2 := uint64(binary.LittleEndian.Uint32(buf[6:]))
	t3 := uint64(binary.LittleEndian.Uint32(buf[9:]))
	t4 := uint64(binary.LittleEndian.Uint32(buf[12:]))
	hibit := uint64(buf[16]) << 24
	p.h0 += t0 & 0x3ffffff
	p.h1 += (t1 >> 2) & 0x3ffffff
	p.h2 += (t2 >> 4) & 0x3ffffff
	p.h3 += (t3 >> 6) & 0x3ffffff
	p.h4 += (t4 >> 8) | hibit
	r0, r1, r2, r3, r4 := p.r0, p.r1, p.r2, p.r3, p.r4
	s1, s2, s3, s4 := r1*5, r2*5, r3*5, r4*5
	d0 := p.h0*r0 + p.h1*s4 + p.h2*s3 + p.h3*s2 + p.h4*s1
	d1 := p.h0*r1 + p.h1*r0 + p.h2*s4 + p.h3*s3 + p.h4*s2
	d2 := p.h0*r2 + p.h1*r1 + p.h2*r0 + p.h3*s4 + p.h4*s3
	d3 := p.h0*r3 + p.h1*r2 + p.h2*r1 + p.h3*r0 + p.h4*s4
	d4 := p.h0*r4 + p.h1*r3 + p.h2*r2 + p.h3*r1 + p.h4*r0
	c := d0 >> 26
	p.h0 = d0 & 0x3ffffff
	d1 += c
	c = d1 >> 26
	p.h1 = d1 & 0x3ffffff
	d2 += c
	c = d2 >> 26
	p.h2 = d2 & 0x3ffffff
	d3 += c
	c = d3 >> 26
	p.h3 = d3 & 0x3ffffff
	d4 += c
	c = d4 >> 26
	p.h4 = d4 & 0x3ffffff
	p.h0 += c * 5
	c = p.h0 >> 26
	p.h0 &= 0x3ffffff
	p.h1 += c
}

func (p *poly1305) write(m []byte) {
	for len(m) >= 16 {
		p.block(m[:16], false)
		m = m[16:]
	}
	if len(m) > 0 {
		p.block(m, true)
	}
}

func (p *poly1305) writePadded(m []byte) {
	for len(m) >= 16 {
		p.block(m[:16], false)
		m = m[16:]
	}
	if len(m) > 0 {
		var pad [16]byte
		copy(pad[:], m)
		p.block(pad[:], false)
	}
}

func (p *poly1305) sum() [16]byte {
	h0, h1, h2, h3, h4 := p.h0, p.h1, p.h2, p.h3, p.h4
	c := h1 >> 26
	h1 &= 0x3ffffff
	h2 += c
	c = h2 >> 26
	h2 &= 0x3ffffff
	h3 += c
	c = h3 >> 26
	h3 &= 0x3ffffff
	h4 += c
	c = h4 >> 26
	h4 &= 0x3ffffff
	h0 += c * 5
	c = h0 >> 26
	h0 &= 0x3ffffff
	h1 += c
	g0 := h0 + 5
	c = g0 >> 26
	g0 &= 0x3ffffff
	g1 := h1 + c
	c = g1 >> 26
	g1 &= 0x3ffffff
	g2 := h2 + c
	c = g2 >> 26
	g2 &= 0x3ffffff
	g3 := h3 + c
	c = g3 >> 26
	g3 &= 0x3ffffff
	g4 := h4 + c - (1 << 26)
	mask := (g4 >> 63) - 1
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ^mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4
	h0 = (h0 | (h1 << 26)) & 0xffffffff
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff
	f := h0 + p.s0
	h0 = f & 0xffffffff
	f = h1 + p.s1 + (f >> 32)
	h1 = f & 0xffffffff
	f = h2 + p.s2 + (f >> 32)
	h2 = f & 0xffffffff
	f = h3 + p.s3 + (f >> 32)
	h3 = f & 0xffffffff
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], uint32(h0))
	binary.LittleEndian.PutUint32(out[4:], uint32(h1))
	binary.LittleEndian.PutUint32(out[8:], uint32(h2))
	binary.LittleEndian.PutUint32(out[12:], uint32(h3))
	return out
}

type chacha20poly1305 struct {
	key [32]byte
}

func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	a := &chacha20poly1305{}
	copy(a.key[:], key)
	return a, nil
}

func (a *chacha20poly1305) NonceSize() int { return 12 }
func (a *chacha20poly1305) Overhead() int  { return 16 }

func (a *chacha20poly1305) tag(nonce, ciphertext, ad []byte) [16]byte {
	var polyKey [64]byte
	chachaBlock(chachaKey(a.key[:]), 0, chachaNonce(nonce), &polyKey)
	p := newPoly1305(polyKey[:32])
	p.writePadded(ad)
	p.writePadded(ciphertext)
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:], uint64(len(ad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ciphertext)))
	p.write(lens[:])
	return p.sum()
}

func (a *chacha20poly1305) Seal(dst, nonce, plaintext, ad []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+16)
	chachaXOR(a.key[:], 1, nonce, out[:len(plaintext)], plaintext)
	t := a.tag(nonce, out[:len(plaintext)], ad)
	copy(out[len(plaintext):], t[:])
	return ret
}

func (a *chacha20poly1305) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}
	ct := ciphertext[:len(ciphertext)-16]
	t := a.tag(nonce, ct, ad)
	if subtle.ConstantTimeCompare(t[:], ciphertext[len(ct):]) != 1 {
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}
	ret, out := sliceForAppend(dst, len(ct))
	chachaXOR(a.key[:], 1, nonce, out, ct)
	return ret, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
