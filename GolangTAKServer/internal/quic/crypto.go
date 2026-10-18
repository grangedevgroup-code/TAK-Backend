package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"hash"
)

var initialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(h, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

type keys struct {
	aead   cipher.AEAD
	iv     []byte
	hpAES  cipher.Block
	hpCC   []byte
	secret []byte
	suite  uint16
}

func suiteHash(suite uint16) func() hash.Hash {
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		return sha512.New384
	}
	return sha256.New
}

func newKeys(suite uint16, secret []byte) (*keys, error) {
	h := suiteHash(suite)
	k := &keys{secret: secret, suite: suite}
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		n := 16
		if suite == tls.TLS_AES_256_GCM_SHA384 {
			n = 32
		}
		block, err := aes.NewCipher(hkdfExpandLabel(h, secret, "quic key", nil, n))
		if err != nil {
			return nil, err
		}
		if k.aead, err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
		if k.hpAES, err = aes.NewCipher(hkdfExpandLabel(h, secret, "quic hp", nil, n)); err != nil {
			return nil, err
		}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		var err error
		if k.aead, err = newChaCha20Poly1305(hkdfExpandLabel(h, secret, "quic key", nil, 32)); err != nil {
			return nil, err
		}
		k.hpCC = hkdfExpandLabel(h, secret, "quic hp", nil, 32)
	default:
		return nil, errors.New("quic: unsupported cipher suite")
	}
	k.iv = hkdfExpandLabel(h, secret, "quic iv", nil, 12)
	return k, nil
}

func (k *keys) next() (*keys, error) {
	ns := hkdfExpandLabel(suiteHash(k.suite), k.secret, "quic ku", nil, len(k.secret))
	nk, err := newKeys(k.suite, ns)
	if err != nil {
		return nil, err
	}
	nk.hpAES, nk.hpCC = k.hpAES, k.hpCC
	return nk, nil
}

func (k *keys) mask(sample []byte) [5]byte {
	var m [5]byte
	if k.hpAES != nil {
		var out [16]byte
		k.hpAES.Encrypt(out[:], sample)
		copy(m[:], out[:5])
		return m
	}
	counter := binary.LittleEndian.Uint32(sample[0:4])
	var zero [5]byte
	chachaXOR(k.hpCC, counter, sample[4:16], m[:], zero[:])
	return m
}

func (k *keys) nonce(pn uint64) []byte {
	n := make([]byte, 12)
	copy(n, k.iv)
	for i := 0; i < 8; i++ {
		n[11-i] ^= byte(pn >> (8 * i))
	}
	return n
}

func initialKeys(dcid []byte, server bool) (rx, tx *keys) {
	initial, err := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	if err != nil {
		panic(err)
	}
	cs := hkdfExpandLabel(sha256.New, initial, "client in", nil, 32)
	ss := hkdfExpandLabel(sha256.New, initial, "server in", nil, 32)
	ck, _ := newKeys(tls.TLS_AES_128_GCM_SHA256, cs)
	sk, _ := newKeys(tls.TLS_AES_128_GCM_SHA256, ss)
	if server {
		return ck, sk
	}
	return sk, ck
}
