package mumble

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const blockSize = 16

type cryptState struct {
	mu        sync.Mutex
	key       [16]byte
	encryptIV [16]byte
	decryptIV [16]byte
	history   [256]byte
	block     cipher.Block
	good      atomic.Uint32
	late      atomic.Uint32
	lost      atomic.Uint32
}

func newCryptState() *cryptState {
	c := &cryptState{}
	randomBytes(c.key[:])
	randomBytes(c.encryptIV[:])
	randomBytes(c.decryptIV[:])
	c.block, _ = aes.NewCipher(c.key[:])
	return c
}

func s2(b *[16]byte) {
	carry := b[0] >> 7
	for i := 0; i < 15; i++ {
		b[i] = b[i]<<1 | b[i+1]>>7
	}
	b[15] = b[15]<<1 ^ carry*0x87
}

func s3(b *[16]byte) {
	t := *b
	s2(b)
	for i := range b {
		b[i] ^= t[i]
	}
}

func xor(dst, a, b []byte) {
	for i := 0; i < blockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func (c *cryptState) ocbEncrypt(plain, enc []byte, nonce [16]byte) [16]byte {
	var delta, checksum, tmp, pad [16]byte
	c.block.Encrypt(delta[:], nonce[:])
	n := len(plain)
	off := 0
	for n > blockSize {
		flip := false
		if n-blockSize <= blockSize {
			var sum byte
			for i := 0; i < blockSize-1; i++ {
				sum |= plain[off+i]
			}
			flip = sum == 0
		}
		s2(&delta)
		xor(tmp[:], delta[:], plain[off:])
		if flip {
			tmp[0] ^= 1
		}
		c.block.Encrypt(tmp[:], tmp[:])
		xor(enc[off:], delta[:], tmp[:])
		xor(checksum[:], checksum[:], plain[off:])
		if flip {
			checksum[0] ^= 1
		}
		n -= blockSize
		off += blockSize
	}
	s2(&delta)
	tmp = [16]byte{}
	binary.BigEndian.PutUint32(tmp[12:], uint32(n*8))
	xor(tmp[:], tmp[:], delta[:])
	c.block.Encrypt(pad[:], tmp[:])
	copy(tmp[:], plain[off:off+n])
	copy(tmp[n:], pad[n:])
	xor(checksum[:], checksum[:], tmp[:])
	xor(tmp[:], tmp[:], pad[:])
	copy(enc[off:], tmp[:n])
	s3(&delta)
	var tag [16]byte
	xor(tmp[:], delta[:], checksum[:])
	c.block.Encrypt(tag[:], tmp[:])
	return tag
}

func (c *cryptState) ocbDecrypt(enc, plain []byte, nonce [16]byte) ([16]byte, bool) {
	var delta, checksum, tmp, pad [16]byte
	c.block.Encrypt(delta[:], nonce[:])
	n := len(enc)
	off := 0
	for n > blockSize {
		s2(&delta)
		xor(tmp[:], delta[:], enc[off:])
		c.block.Decrypt(tmp[:], tmp[:])
		xor(plain[off:], delta[:], tmp[:])
		xor(checksum[:], checksum[:], plain[off:])
		n -= blockSize
		off += blockSize
	}
	s2(&delta)
	tmp = [16]byte{}
	binary.BigEndian.PutUint32(tmp[12:], uint32(n*8))
	xor(tmp[:], tmp[:], delta[:])
	c.block.Encrypt(pad[:], tmp[:])
	tmp = [16]byte{}
	copy(tmp[:], enc[off:off+n])
	xor(tmp[:], tmp[:], pad[:])
	xor(checksum[:], checksum[:], tmp[:])
	copy(plain[off:], tmp[:n])
	ok := subtle.ConstantTimeCompare(tmp[:blockSize-1], delta[:blockSize-1]) != 1
	s3(&delta)
	var tag [16]byte
	xor(tmp[:], delta[:], checksum[:])
	c.block.Encrypt(tag[:], tmp[:])
	return tag, ok
}

func (c *cryptState) encrypt(plain []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.encryptIV {
		c.encryptIV[i]++
		if c.encryptIV[i] != 0 {
			break
		}
	}
	out := make([]byte, len(plain)+4)
	tag := c.ocbEncrypt(plain, out[4:], c.encryptIV)
	out[0] = c.encryptIV[0]
	copy(out[1:4], tag[:3])
	return out
}

var errDecrypt = errors.New("voice packet failed to decrypt")

func (c *cryptState) decrypt(src []byte) ([]byte, error) {
	if len(src) < 4 {
		return nil, errDecrypt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	save := c.decryptIV
	ivbyte := src[0]
	restore := false
	late, lost := 0, 0
	if c.decryptIV[0]+1 == ivbyte {
		if ivbyte > c.decryptIV[0] {
			c.decryptIV[0] = ivbyte
		} else if ivbyte < c.decryptIV[0] {
			c.decryptIV[0] = ivbyte
			for i := 1; i < 16; i++ {
				c.decryptIV[i]++
				if c.decryptIV[i] != 0 {
					break
				}
			}
		} else {
			return nil, errDecrypt
		}
	} else {
		diff := int(ivbyte) - int(c.decryptIV[0])
		if diff > 128 {
			diff -= 256
		} else if diff < -128 {
			diff += 256
		}
		switch {
		case ivbyte < c.decryptIV[0] && diff > -30 && diff < 0:
			late, lost = 1, -1
			c.decryptIV[0] = ivbyte
			restore = true
		case ivbyte > c.decryptIV[0] && diff > -30 && diff < 0:
			late, lost = 1, -1
			c.decryptIV[0] = ivbyte
			for i := 1; i < 16; i++ {
				c.decryptIV[i]--
				if c.decryptIV[i] != 0xff {
					break
				}
			}
			restore = true
		case ivbyte > c.decryptIV[0] && diff > 0:
			lost = int(ivbyte) - int(c.decryptIV[0]) - 1
			c.decryptIV[0] = ivbyte
		case ivbyte < c.decryptIV[0] && diff > 0:
			lost = 256 - int(c.decryptIV[0]) + int(ivbyte) - 1
			c.decryptIV[0] = ivbyte
			for i := 1; i < 16; i++ {
				c.decryptIV[i]++
				if c.decryptIV[i] != 0 {
					break
				}
			}
		default:
			return nil, errDecrypt
		}
		if c.history[c.decryptIV[0]] == c.decryptIV[1] {
			c.decryptIV = save
			return nil, errDecrypt
		}
	}
	plain := make([]byte, len(src)-4)
	tag, ok := c.ocbDecrypt(src[4:], plain, c.decryptIV)
	if !ok || subtle.ConstantTimeCompare(tag[:3], src[1:4]) != 1 {
		c.decryptIV = save
		return nil, errDecrypt
	}
	c.history[c.decryptIV[0]] = c.decryptIV[1]
	if restore {
		c.decryptIV = save
	}
	c.good.Add(1)
	if late > 0 {
		c.late.Add(uint32(late))
	}
	if lost > 0 {
		c.lost.Add(uint32(lost))
	}
	return plain, nil
}

func (s *Server) ListenUDP(pc *net.UDPConn) {
	s.mu.Lock()
	s.udp = pc
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 2048)
		byAddr := map[string]*user{}
		lastClean := time.Now()
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			pkt := buf[:n]
			if n == 12 && binary.BigEndian.Uint32(pkt) == 0 {
				s.mu.Lock()
				count := len(s.users)
				s.mu.Unlock()
				reply := binary.BigEndian.AppendUint32(nil, serverVersion)
				reply = append(reply, pkt[4:12]...)
				reply = binary.BigEndian.AppendUint32(reply, uint32(count))
				reply = binary.BigEndian.AppendUint32(reply, uint32(s.MaxUsers))
				reply = binary.BigEndian.AppendUint32(reply, maxBandwidth)
				pc.WriteToUDP(reply, addr)
				continue
			}
			if time.Since(lastClean) > time.Minute {
				for k, u := range byAddr {
					select {
					case <-u.done:
						delete(byAddr, k)
					default:
					}
				}
				lastClean = time.Now()
			}
			key := addr.String()
			u := byAddr[key]
			var plain []byte
			if u != nil {
				plain, err = u.crypt.decrypt(pkt)
				if err != nil {
					continue
				}
			} else {
				s.mu.Lock()
				var cands []*user
				for _, o := range s.users {
					if ra, ok := o.nc.RemoteAddr().(*net.TCPAddr); ok && ra.IP.Equal(addr.IP) && o.crypt != nil {
						cands = append(cands, o)
					}
				}
				s.mu.Unlock()
				for _, o := range cands {
					if p, err := o.crypt.decrypt(pkt); err == nil {
						u, plain = o, p
						break
					}
				}
				if u == nil {
					continue
				}
				byAddr[key] = u
				u.udpAddr.Store(addr)
			}
			if len(plain) > 0 {
				s.voice(u, plain, true)
			}
		}
	}()
}
