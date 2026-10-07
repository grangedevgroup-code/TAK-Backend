package pki

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"hash"
)

const p12Iterations = 2048

var (
	oidData              = oid(1, 2, 840, 113549, 1, 7, 1)
	oidEncryptedData     = oid(1, 2, 840, 113549, 1, 7, 6)
	oidCertBag           = oid(1, 2, 840, 113549, 1, 12, 10, 1, 3)
	oidKeyBag            = oid(1, 2, 840, 113549, 1, 12, 10, 1, 1)
	oidShroudedKeyBag    = oid(1, 2, 840, 113549, 1, 12, 10, 1, 2)
	oidX509Cert          = oid(1, 2, 840, 113549, 1, 9, 22, 1)
	oidFriendlyName      = oid(1, 2, 840, 113549, 1, 9, 20)
	oidLocalKeyID        = oid(1, 2, 840, 113549, 1, 9, 21)
	oidJavaTrusted       = oid(2, 16, 840, 1, 113894, 746875, 1, 1)
	oidAnyExtendedKeyUse = oid(2, 5, 29, 37, 0)
	oidPBEWithSHA3DES    = oid(1, 2, 840, 113549, 1, 12, 1, 3)
	oidPBES2             = oid(1, 2, 840, 113549, 1, 5, 13)
	oidPBKDF2            = oid(1, 2, 840, 113549, 1, 5, 12)
	oidHMACSHA1          = oid(1, 2, 840, 113549, 2, 7)
	oidHMACSHA256        = oid(1, 2, 840, 113549, 2, 9)
	oidHMACSHA512        = oid(1, 2, 840, 113549, 2, 11)
	oidAES128CBC         = oid(2, 16, 840, 1, 101, 3, 4, 1, 2)
	oidAES192CBC         = oid(2, 16, 840, 1, 101, 3, 4, 1, 22)
	oidAES256CBC         = oid(2, 16, 840, 1, 101, 3, 4, 1, 42)
	oidDESEDE3CBC        = oid(1, 2, 840, 113549, 3, 7)
	oidSHA1              = oid(1, 3, 14, 3, 2, 26)
	oidSHA256            = oid(2, 16, 840, 1, 101, 3, 4, 2, 1)
	oidSHA512            = oid(2, 16, 840, 1, 101, 3, 4, 2, 3)
	ErrWrongPassword     = errors.New("pki: wrong password or corrupt PKCS#12 file")
	ErrUnsupportedPKCS12 = errors.New("pki: unsupported PKCS#12 encryption")
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func fill(b []byte, v int) []byte {
	if len(b) == 0 {
		return nil
	}
	n := v * ((len(b) + v - 1) / v)
	out := make([]byte, n)
	for i := 0; i < n; i += len(b) {
		copy(out[i:], b)
	}
	return out
}

func pkcs12KDF(newHash func() hash.Hash, u, v int, password, salt []byte, id byte, iterations, size int) []byte {
	d := bytes.Repeat([]byte{id}, v)
	i := append(fill(salt, v), fill(password, v)...)
	c := (size + u - 1) / u
	out := make([]byte, 0, c*u)
	h := newHash()
	for n := 0; n < c; n++ {
		h.Reset()
		h.Write(d)
		h.Write(i)
		a := h.Sum(nil)
		for k := 1; k < iterations; k++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)
		if n < c-1 {
			bb := fill(a, v)[:v]
			for j := 0; j+v <= len(i); j += v {
				blk := i[j : j+v]
				carry := 1
				for k := v - 1; k >= 0; k-- {
					sum := int(blk[k]) + int(bb[k]) + carry
					blk[k] = byte(sum)
					carry = sum >> 8
				}
			}
		}
	}
	return out[:size]
}

func sha1KDF(password, salt []byte, id byte, iterations, size int) []byte {
	return pkcs12KDF(sha1.New, sha1.Size, 64, password, salt, id, iterations, size)
}

func pad(b []byte, block int) []byte {
	n := block - len(b)%block
	return append(append([]byte(nil), b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 || len(b)%block != 0 {
		return nil, ErrWrongPassword
	}
	n := int(b[len(b)-1])
	if n == 0 || n > block || n > len(b) {
		return nil, ErrWrongPassword
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, ErrWrongPassword
		}
	}
	return b[:len(b)-n], nil
}

func pbeAlgorithm(salt []byte, iterations int) []byte {
	return seq(oidPBEWithSHA3DES, seq(octet(salt), integer(int64(iterations))))
}

func pbeEncrypt(plain []byte, password string, salt []byte, iterations int) []byte {
	pw := bmpPassword(password)
	key := sha1KDF(pw, salt, 1, iterations, 24)
	iv := sha1KDF(pw, salt, 2, iterations, 8)
	block, _ := des.NewTripleDESCipher(key)
	data := pad(plain, 8)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	return data
}

func safeBag(bagID, value []byte, attrs ...[]byte) []byte {
	if len(attrs) == 0 {
		return seq(bagID, explicit(0, value))
	}
	return seq(bagID, explicit(0, value), set(attrs...))
}

func attribute(id []byte, values ...[]byte) []byte {
	return seq(id, set(values...))
}

func certBag(c *x509.Certificate, attrs ...[]byte) []byte {
	return safeBag(oidCertBag, seq(oidX509Cert, explicit(0, octet(c.Raw))), attrs...)
}

func encryptedContentInfo(content []byte, password string) []byte {
	salt := randomBytes(8)
	enc := pbeEncrypt(content, password, salt, p12Iterations)
	encData := seq(integer(0), seq(oidData, pbeAlgorithm(salt, p12Iterations), implicitPrimitive(0, enc)))
	return seq(oidEncryptedData, explicit(0, encData))
}

func pfx(authSafe []byte, password string) []byte {
	salt := randomBytes(8)
	key := sha1KDF(bmpPassword(password), salt, 3, p12Iterations, 20)
	mac := hmac.New(sha1.New, key)
	mac.Write(authSafe)
	macData := seq(seq(seq(oidSHA1, null()), octet(mac.Sum(nil))), octet(salt), integer(p12Iterations))
	return seq(integer(3), seq(oidData, explicit(0, octet(authSafe))), macData)
}

func EncodePKCS12(key crypto.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate, password, alias string) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if alias == "" {
		alias = cert.Subject.CommonName
	}
	sum := sha1.Sum(cert.Raw)
	localID := attribute(oidLocalKeyID, octet(sum[:]))
	name := attribute(oidFriendlyName, bmpString(alias))
	bags := [][]byte{certBag(cert, name, localID)}
	for _, c := range chain {
		bags = append(bags, certBag(c, attribute(oidFriendlyName, bmpString(c.Subject.CommonName))))
	}
	certsInfo := encryptedContentInfo(seq(bags...), password)
	salt := randomBytes(8)
	encKey := pbeEncrypt(pkcs8, password, salt, p12Iterations)
	keyInfo := seq(pbeAlgorithm(salt, p12Iterations), octet(encKey))
	keyContents := seq(safeBag(oidShroudedKeyBag, keyInfo, name, localID))
	keyData := seq(oidData, explicit(0, octet(keyContents)))
	return pfx(seq(certsInfo, keyData), password), nil
}

func EncodeTrustStore(certs []*x509.Certificate, password string, aliases ...string) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("pki: no certificates")
	}
	var bags [][]byte
	for i, c := range certs {
		alias := c.Subject.CommonName
		if i < len(aliases) && aliases[i] != "" {
			alias = aliases[i]
		}
		bags = append(bags, certBag(c,
			attribute(oidFriendlyName, bmpString(alias)),
			attribute(oidJavaTrusted, oidAnyExtendedKeyUse)))
	}
	return pfx(seq(encryptedContentInfo(seq(bags...), password)), password), nil
}

type PKCS12 struct {
	Key   crypto.PrivateKey
	Cert  *x509.Certificate
	Certs []*x509.Certificate
}

func DecodePKCS12(data []byte, password string) (*PKCS12, error) {
	root, _, err := readElem(data)
	if err != nil || root.tag != 0x30 {
		return nil, errDER
	}
	parts, err := children(root.content)
	if err != nil || len(parts) < 2 {
		return nil, errDER
	}
	if v, err := parseInt(parts[0]); err != nil || v != 3 {
		return nil, ErrUnsupportedPKCS12
	}
	ci, err := children(parts[1].content)
	if err != nil || len(ci) != 2 || !sameOID(ci[0], oidData) || ci[1].tag != 0xa0 {
		return nil, errDER
	}
	inner, _, err := readElem(ci[1].content)
	if err != nil || inner.tag != 0x04 {
		return nil, errDER
	}
	authSafe := inner.content
	if len(parts) > 2 {
		if err := verifyMAC(parts[2], authSafe, password); err != nil {
			return nil, err
		}
	}
	asRoot, _, err := readElem(authSafe)
	if err != nil || asRoot.tag != 0x30 {
		return nil, errDER
	}
	infos, err := children(asRoot.content)
	if err != nil {
		return nil, err
	}
	out := &PKCS12{}
	var keyIDs [][]byte
	var certIDs [][]byte
	for _, info := range infos {
		f, err := children(info.content)
		if err != nil || len(f) < 2 || f[1].tag != 0xa0 {
			return nil, errDER
		}
		var contents []byte
		switch {
		case sameOID(f[0], oidData):
			o, _, err := readElem(f[1].content)
			if err != nil || o.tag != 0x04 {
				return nil, errDER
			}
			contents = o.content
		case sameOID(f[0], oidEncryptedData):
			ed, _, err := readElem(f[1].content)
			if err != nil {
				return nil, errDER
			}
			edf, err := children(ed.content)
			if err != nil || len(edf) < 2 {
				return nil, errDER
			}
			eci, err := children(edf[1].content)
			if err != nil || len(eci) < 3 {
				return nil, errDER
			}
			enc := eci[2].content
			if eci[2].tag == 0xa0 {
				var buf []byte
				rest := eci[2].content
				for len(rest) > 0 {
					var e elem
					e, rest, err = readElem(rest)
					if err != nil {
						return nil, errDER
					}
					buf = append(buf, e.content...)
				}
				enc = buf
			}
			contents, err = decrypt(eci[1], enc, password)
			if err != nil {
				return nil, err
			}
		default:
			continue
		}
		sc, _, err := readElem(contents)
		if err != nil || sc.tag != 0x30 {
			return nil, errDER
		}
		bags, err := children(sc.content)
		if err != nil {
			return nil, err
		}
		for _, bag := range bags {
			bf, err := children(bag.content)
			if err != nil || len(bf) < 2 || bf[1].tag != 0xa0 {
				return nil, errDER
			}
			value, _, err := readElem(bf[1].content)
			if err != nil {
				return nil, errDER
			}
			var localID []byte
			if len(bf) > 2 {
				localID = findLocalKeyID(bf[2])
			}
			switch {
			case sameOID(bf[0], oidCertBag):
				cf, err := children(value.content)
				if err != nil || len(cf) < 2 || !sameOID(cf[0], oidX509Cert) {
					continue
				}
				raw, _, err := readElem(cf[1].content)
				if err != nil || raw.tag != 0x04 {
					return nil, errDER
				}
				c, err := x509.ParseCertificate(raw.content)
				if err != nil {
					return nil, err
				}
				out.Certs = append(out.Certs, c)
				certIDs = append(certIDs, localID)
			case sameOID(bf[0], oidShroudedKeyBag):
				kf, err := children(value.content)
				if err != nil || len(kf) < 2 {
					return nil, errDER
				}
				plain, err := decrypt(kf[0], kf[1].content, password)
				if err != nil {
					return nil, err
				}
				k, err := x509.ParsePKCS8PrivateKey(plain)
				if err != nil {
					return nil, err
				}
				out.Key = k
				keyIDs = append(keyIDs, localID)
			case sameOID(bf[0], oidKeyBag):
				k, err := x509.ParsePKCS8PrivateKey(value.full)
				if err != nil {
					return nil, err
				}
				out.Key = k
				keyIDs = append(keyIDs, localID)
			}
		}
	}
	if out.Key != nil {
		for i, c := range out.Certs {
			if len(keyIDs) > 0 && keyIDs[0] != nil && bytes.Equal(certIDs[i], keyIDs[0]) {
				out.Cert = c
				break
			}
		}
		if out.Cert == nil {
			if pub, ok := out.Key.(interface{ Public() crypto.PublicKey }); ok {
				for _, c := range out.Certs {
					if eq, ok := c.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && eq.Equal(pub.Public()) {
						out.Cert = c
						break
					}
				}
			}
		}
	}
	return out, nil
}

func findLocalKeyID(attrs elem) []byte {
	list, err := children(attrs.content)
	if err != nil {
		return nil
	}
	for _, a := range list {
		f, err := children(a.content)
		if err != nil || len(f) < 2 || !sameOID(f[0], oidLocalKeyID) {
			continue
		}
		v, _, err := readElem(f[1].content)
		if err == nil && v.tag == 0x04 {
			return v.content
		}
	}
	return nil
}

func verifyMAC(macData elem, authSafe []byte, password string) error {
	f, err := children(macData.content)
	if err != nil || len(f) < 2 {
		return errDER
	}
	di, err := children(f[0].content)
	if err != nil || len(di) != 2 {
		return errDER
	}
	alg, err := children(di[0].content)
	if err != nil || len(alg) < 1 {
		return errDER
	}
	salt := f[1].content
	iter := 1
	if len(f) > 2 {
		if iter, err = parseInt(f[2]); err != nil {
			return err
		}
	}
	var newHash func() hash.Hash
	var u int
	switch {
	case sameOID(alg[0], oidSHA1):
		newHash, u = sha1.New, sha1.Size
	case sameOID(alg[0], oidSHA256):
		newHash, u = sha256.New, sha256.Size
	case sameOID(alg[0], oidSHA512):
		newHash, u = sha512.New, sha512.Size
	default:
		return ErrUnsupportedPKCS12
	}
	v := 64
	if u == sha512.Size {
		v = 128
	}
	key := pkcs12KDF(newHash, u, v, bmpPassword(password), salt, 3, iter, u)
	m := hmac.New(newHash, key)
	m.Write(authSafe)
	if !hmac.Equal(m.Sum(nil), di[1].content) {
		return ErrWrongPassword
	}
	return nil
}

func decrypt(algID elem, enc []byte, password string) ([]byte, error) {
	f, err := children(algID.content)
	if err != nil || len(f) < 2 {
		return nil, errDER
	}
	params, err := children(f[1].content)
	if err != nil {
		return nil, errDER
	}
	switch {
	case sameOID(f[0], oidPBEWithSHA3DES):
		if len(params) < 2 {
			return nil, errDER
		}
		iter, err := parseInt(params[1])
		if err != nil {
			return nil, err
		}
		pw := bmpPassword(password)
		key := sha1KDF(pw, params[0].content, 1, iter, 24)
		iv := sha1KDF(pw, params[0].content, 2, iter, 8)
		block, _ := des.NewTripleDESCipher(key)
		if len(enc)%8 != 0 || len(enc) == 0 {
			return nil, ErrWrongPassword
		}
		out := append([]byte(nil), enc...)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, out)
		return unpad(out, 8)
	case sameOID(f[0], oidPBES2):
		if len(params) < 2 {
			return nil, errDER
		}
		kdf, err := children(params[0].content)
		if err != nil || len(kdf) < 2 || !sameOID(kdf[0], oidPBKDF2) {
			return nil, ErrUnsupportedPKCS12
		}
		kp, err := children(kdf[1].content)
		if err != nil || len(kp) < 2 {
			return nil, errDER
		}
		salt := kp[0].content
		iter, err := parseInt(kp[1])
		if err != nil {
			return nil, err
		}
		prf := sha1.New
		for _, x := range kp[2:] {
			if x.tag != 0x30 {
				continue
			}
			pf, err := children(x.content)
			if err != nil || len(pf) < 1 {
				continue
			}
			switch {
			case sameOID(pf[0], oidHMACSHA256):
				prf = sha256.New
			case sameOID(pf[0], oidHMACSHA512):
				prf = sha512.New
			case sameOID(pf[0], oidHMACSHA1):
				prf = sha1.New
			}
		}
		es, err := children(params[1].content)
		if err != nil || len(es) < 2 {
			return nil, errDER
		}
		iv := es[1].content
		var keyLen int
		var newBlock func([]byte) (cipher.Block, error)
		switch {
		case sameOID(es[0], oidAES128CBC):
			keyLen, newBlock = 16, aes.NewCipher
		case sameOID(es[0], oidAES192CBC):
			keyLen, newBlock = 24, aes.NewCipher
		case sameOID(es[0], oidAES256CBC):
			keyLen, newBlock = 32, aes.NewCipher
		case sameOID(es[0], oidDESEDE3CBC):
			keyLen, newBlock = 24, des.NewTripleDESCipher
		default:
			return nil, ErrUnsupportedPKCS12
		}
		key, err := pbkdf2.Key(prf, password, salt, iter, keyLen)
		if err != nil {
			return nil, err
		}
		block, err := newBlock(key)
		if err != nil {
			return nil, err
		}
		bs := block.BlockSize()
		if len(iv) != bs || len(enc)%bs != 0 || len(enc) == 0 {
			return nil, ErrWrongPassword
		}
		out := append([]byte(nil), enc...)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, out)
		return unpad(out, bs)
	}
	return nil, ErrUnsupportedPKCS12
}
