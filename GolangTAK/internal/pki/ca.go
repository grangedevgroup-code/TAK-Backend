package pki

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var OIDChannels = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

type CA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	CertPEM []byte
}

func NewSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

func SerialHex(c *x509.Certificate) string {
	return strings.ToLower(c.SerialNumber.Text(16))
}

func Fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(s[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func keyID(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil
	}
	s := sha1.Sum(spki.PublicKey.Bytes)
	return s[:]
}

func NewKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func KeyPEM(k crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func PEMBody(c *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(c.Raw)
}

func ParseCertPEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" && blk.Type != "TRUSTED CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("pki: no certificate found in PEM data")
	}
	return out, nil
}

func ParseKeyPEM(b []byte, password string) (crypto.Signer, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("pki: no private key found in PEM data")
		}
		if !strings.Contains(blk.Type, "PRIVATE KEY") {
			continue
		}
		der := blk.Bytes
		if strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED") {
			if password == "" {
				return nil, errors.New("pki: private key is encrypted; a password is required")
			}
			var err error
			der, err = decryptLegacyPEM(blk, password)
			if err != nil {
				return nil, err
			}
		}
		if blk.Type == "ENCRYPTED PRIVATE KEY" {
			plain, err := decryptPKCS8(der, password)
			if err != nil {
				return nil, err
			}
			der = plain
		}
		return parseKeyDER(der)
	}
}

func decryptLegacyPEM(blk *pem.Block, password string) ([]byte, error) {
	info := strings.SplitN(blk.Headers["DEK-Info"], ",", 2)
	if len(info) != 2 {
		return nil, ErrUnsupportedPKCS12
	}
	iv, err := hex.DecodeString(strings.TrimSpace(info[1]))
	if err != nil || len(iv) < 8 {
		return nil, errDER
	}
	var keyLen int
	var newBlock func([]byte) (cipher.Block, error)
	switch strings.ToUpper(strings.TrimSpace(info[0])) {
	case "DES-CBC":
		keyLen, newBlock = 8, des.NewCipher
	case "DES-EDE3-CBC":
		keyLen, newBlock = 24, des.NewTripleDESCipher
	case "AES-128-CBC":
		keyLen, newBlock = 16, aes.NewCipher
	case "AES-192-CBC":
		keyLen, newBlock = 24, aes.NewCipher
	case "AES-256-CBC":
		keyLen, newBlock = 32, aes.NewCipher
	default:
		return nil, ErrUnsupportedPKCS12
	}
	var key, prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		h.Write(iv[:8])
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	block, err := newBlock(key[:keyLen])
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(blk.Bytes)%block.BlockSize() != 0 || len(blk.Bytes) == 0 {
		return nil, ErrWrongPassword
	}
	out := append([]byte(nil), blk.Bytes...)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, out)
	return unpad(out, block.BlockSize())
}

func decryptPKCS8(der []byte, password string) ([]byte, error) {
	root, _, err := readElem(der)
	if err != nil || root.tag != 0x30 {
		return nil, errDER
	}
	f, err := children(root.content)
	if err != nil || len(f) < 2 {
		return nil, errDER
	}
	return decrypt(f[0], f[1].content, password)
}

func parseKeyDER(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("pki: unsupported key type")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("pki: unrecognised private key format")
}

func PublicKeysEqual(a, b crypto.PublicKey) bool {
	switch k := a.(type) {
	case *rsa.PublicKey:
		return k.Equal(b)
	case *ecdsa.PublicKey:
		return k.Equal(b)
	case ed25519.PublicKey:
		return k.Equal(b)
	}
	return false
}

func NewCA(subject pkix.Name, bits int, years int) (*CA, error) {
	key, err := NewKey(bits)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          NewSerial(),
		Subject:               subject,
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(years, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: CertPEM(cert)}, nil
}

func LoadCA(certPEM, keyPEM []byte, password string) (*CA, error) {
	certs, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParseKeyPEM(keyPEM, password)
	if err != nil {
		return nil, err
	}
	cert := certs[0]
	if !cert.IsCA {
		return nil, errors.New("pki: certificate is not a certificate authority")
	}
	if !PublicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("pki: private key does not match the certificate")
	}
	return &CA{Cert: cert, Key: key, CertPEM: CertPEM(cert)}, nil
}

func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

func (ca *CA) sign(tmpl *x509.Certificate, pub crypto.PublicKey) (*x509.Certificate, error) {
	tmpl.AuthorityKeyId = ca.Cert.SubjectKeyId
	if len(tmpl.AuthorityKeyId) == 0 {
		tmpl.AuthorityKeyId = keyID(ca.Cert.PublicKey)
	}
	tmpl.SubjectKeyId = keyID(pub)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func NormalizeNames(names []string) ([]string, []net.IP) {
	seen := map[string]bool{}
	var dns []string
	var ips []net.IP
	for _, s := range names {
		s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), "[]"))
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else if validDNS(s) {
			dns = append(dns, s)
		}
	}
	sort.Strings(dns)
	sort.Slice(ips, func(i, j int) bool { return bytes.Compare(ips[i], ips[j]) < 0 })
	return dns, ips
}

func validDNS(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '.' || c == '*' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func (ca *CA) IssueServer(cn string, names []string, key crypto.Signer, validity time.Duration) (*x509.Certificate, error) {
	dns, ips := NormalizeNames(names)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: NewSerial(),
		Subject:      pkix.Name{CommonName: cn, Organization: ca.Cert.Subject.Organization, OrganizationalUnit: ca.Cert.Subject.OrganizationalUnit},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	if tmpl.NotAfter.After(ca.Cert.NotAfter) {
		tmpl.NotAfter = ca.Cert.NotAfter
	}
	return ca.sign(tmpl, key.Public())
}

func (ca *CA) IssueClient(cn string, pub crypto.PublicKey, channels bool, validity time.Duration) (*x509.Certificate, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: NewSerial(),
		Subject:      pkix.Name{CommonName: cn, Organization: ca.Cert.Subject.Organization, OrganizationalUnit: ca.Cert.Subject.OrganizationalUnit},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if channels {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{OIDChannels}
	}
	if tmpl.NotAfter.After(ca.Cert.NotAfter) {
		tmpl.NotAfter = ca.Cert.NotAfter
	}
	return ca.sign(tmpl, pub)
}

func (ca *CA) IssueSubordinate(cn string, key crypto.Signer, validity time.Duration) (*x509.Certificate, error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          NewSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: ca.Cert.Subject.Organization, OrganizationalUnit: ca.Cert.Subject.OrganizationalUnit},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	return ca.sign(tmpl, key.Public())
}

func ParseCSR(body []byte) (*x509.CertificateRequest, error) {
	body = bytes.TrimSpace(body)
	if blk, _ := pem.Decode(body); blk != nil {
		return checkCSR(x509.ParseCertificateRequest(blk.Bytes))
	}
	if csr, err := x509.ParseCertificateRequest(body); err == nil {
		return checkCSR(csr, nil)
	}
	s := string(body)
	for _, marker := range []string{"-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----", "-----BEGIN NEW CERTIFICATE REQUEST-----", "-----END NEW CERTIFICATE REQUEST-----"} {
		s = strings.ReplaceAll(s, marker, "")
	}
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == '"' {
			return -1
		}
		return r
	}, s)
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("pki: certificate request is not valid base64: %w", err)
		}
	}
	return checkCSR(x509.ParseCertificateRequest(der))
}

func checkCSR(csr *x509.CertificateRequest, err error) (*x509.CertificateRequest, error) {
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: certificate request signature is invalid: %w", err)
	}
	return csr, nil
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		if rerr := os.Remove(path); rerr == nil {
			if err2 := os.Rename(name, path); err2 == nil {
				return nil
			}
		}
		os.Remove(name)
		return err
	}
	return nil
}
