package turn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
)

const (
	magicCookie = 0x2112A442
	headerLen   = 20

	methodBinding          = 0x001
	methodAllocate         = 0x003
	methodRefresh          = 0x004
	methodSend             = 0x006
	methodData             = 0x007
	methodCreatePermission = 0x008
	methodChannelBind      = 0x009

	classRequest    = 0x000
	classIndication = 0x010
	classSuccess    = 0x100
	classError      = 0x110

	attrMappedAddress      = 0x0001
	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrErrorCode          = 0x0009
	attrChannelNumber      = 0x000C
	attrLifetime           = 0x000D
	attrXorPeerAddress     = 0x0012
	attrData               = 0x0013
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrXorRelayedAddress  = 0x0016
	attrRequestedTransport = 0x0019
	attrXorMappedAddress   = 0x0020
	attrSoftware           = 0x8022
	attrFingerprint        = 0x8028
)

type attr struct {
	typ   uint16
	value []byte
}

type message struct {
	method uint16
	class  uint16
	txid   [12]byte
	attrs  []attr
	raw    []byte
}

func msgType(method, class uint16) uint16 {
	return (method & 0x000f) | (method&0x0070)<<1 | (method&0x0f80)<<2 | class
}

func splitType(t uint16) (method, class uint16) {
	method = t&0x000f | (t&0x00e0)>>1 | (t&0x3e00)>>2
	class = t & 0x0110
	return
}

func isSTUN(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

func parse(b []byte) (*message, error) {
	if !isSTUN(b) {
		return nil, errors.New("not a STUN message")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+n > len(b) || n%4 != 0 {
		return nil, errors.New("bad STUN length")
	}
	m := &message{raw: b[:headerLen+n]}
	m.method, m.class = splitType(binary.BigEndian.Uint16(b[0:2]))
	copy(m.txid[:], b[8:20])
	p := b[headerLen : headerLen+n]
	for len(p) >= 4 {
		t := binary.BigEndian.Uint16(p[0:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+l > len(p) {
			return nil, errors.New("bad STUN attribute")
		}
		m.attrs = append(m.attrs, attr{t, p[4 : 4+l]})
		adv := 4 + (l+3)&^3
		if adv > len(p) {
			break
		}
		p = p[adv:]
	}
	return m, nil
}

func (m *message) get(t uint16) ([]byte, bool) {
	for _, a := range m.attrs {
		if a.typ == t {
			return a.value, true
		}
	}
	return nil, false
}

type builder struct {
	buf []byte
}

func newBuilder(method, class uint16, txid [12]byte) *builder {
	b := &builder{buf: make([]byte, headerLen, 256)}
	binary.BigEndian.PutUint16(b.buf[0:2], msgType(method, class))
	binary.BigEndian.PutUint32(b.buf[4:8], magicCookie)
	copy(b.buf[8:20], txid[:])
	return b
}

func (b *builder) add(t uint16, v []byte) *builder {
	var h [4]byte
	binary.BigEndian.PutUint16(h[0:2], t)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(v)))
	b.buf = append(b.buf, h[:]...)
	b.buf = append(b.buf, v...)
	for len(b.buf)%4 != 0 {
		b.buf = append(b.buf, 0)
	}
	binary.BigEndian.PutUint16(b.buf[2:4], uint16(len(b.buf)-headerLen))
	return b
}

func (b *builder) integrity(key []byte) *builder {
	binary.BigEndian.PutUint16(b.buf[2:4], uint16(len(b.buf)-headerLen+24))
	mac := hmac.New(sha1.New, key)
	mac.Write(b.buf)
	return b.add(attrMessageIntegrity, mac.Sum(nil))
}

func (b *builder) fingerprint() []byte {
	binary.BigEndian.PutUint16(b.buf[2:4], uint16(len(b.buf)-headerLen+8))
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, crc32.ChecksumIEEE(b.buf)^0x5354554e)
	b.add(attrFingerprint, v)
	return b.buf
}

func errorCode(code int, reason string) []byte {
	v := []byte{0, 0, byte(code / 100), byte(code % 100)}
	return append(v, reason...)
}

func xorAddr(addr *net.UDPAddr, txid [12]byte) []byte {
	ip4 := addr.IP.To4()
	port := uint16(addr.Port) ^ uint16(magicCookie>>16)
	if ip4 != nil {
		v := make([]byte, 8)
		v[1] = 0x01
		binary.BigEndian.PutUint16(v[2:4], port)
		binary.BigEndian.PutUint32(v[4:8], binary.BigEndian.Uint32(ip4)^magicCookie)
		return v
	}
	ip := addr.IP.To16()
	v := make([]byte, 20)
	v[1] = 0x02
	binary.BigEndian.PutUint16(v[2:4], port)
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], magicCookie)
	copy(mask[4:], txid[:])
	for i := 0; i < 16; i++ {
		v[4+i] = ip[i] ^ mask[i]
	}
	return v
}

func parseXorAddr(v []byte, txid [12]byte) (*net.UDPAddr, error) {
	if len(v) < 8 {
		return nil, errors.New("short address")
	}
	port := int(binary.BigEndian.Uint16(v[2:4]) ^ uint16(magicCookie>>16))
	switch v[1] {
	case 0x01:
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(v[4:8])^magicCookie)
		return &net.UDPAddr{IP: ip, Port: port}, nil
	case 0x02:
		if len(v) < 20 {
			return nil, errors.New("short address")
		}
		var mask [16]byte
		binary.BigEndian.PutUint32(mask[0:4], magicCookie)
		copy(mask[4:], txid[:])
		ip := make(net.IP, 16)
		for i := range ip {
			ip[i] = v[4+i] ^ mask[i]
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	return nil, errors.New("unknown address family")
}

func longTermKey(user, realm, pass string) []byte {
	h := md5.Sum([]byte(user + ":" + realm + ":" + pass))
	return h[:]
}

func (m *message) checkIntegrity(key []byte) bool {
	pos := headerLen
	for pos+4 <= len(m.raw) {
		t := binary.BigEndian.Uint16(m.raw[pos : pos+2])
		l := int(binary.BigEndian.Uint16(m.raw[pos+2 : pos+4]))
		if t == attrMessageIntegrity {
			if l != 20 || pos+24 > len(m.raw) {
				return false
			}
			cp := append([]byte(nil), m.raw[:pos]...)
			binary.BigEndian.PutUint16(cp[2:4], uint16(pos-headerLen+24))
			mac := hmac.New(sha1.New, key)
			mac.Write(cp)
			return hmac.Equal(mac.Sum(nil), m.raw[pos+4:pos+24])
		}
		pos += 4 + (l+3)&^3
	}
	return false
}
