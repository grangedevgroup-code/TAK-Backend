package revocation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

type CRL struct {
	RawIssuer  []byte
	Issuer     string
	ThisUpdate time.Time
	NextUpdate time.Time
	Version    int
	revoked    map[string]bool
	tbs        []byte
	sigAlg     x509.SignatureAlgorithm
	sig        []byte
}

type certificateList struct {
	TBS                asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type tbsCertList struct {
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time        `asn1:"optional"`
	RevokedCertificates []revokedEntry   `asn1:"optional"`
	Extensions          []pkix.Extension `asn1:"tag:0,optional,explicit"`
}

type revokedEntry struct {
	SerialNumber   *big.Int
	RevocationDate time.Time
	Extensions     []pkix.Extension `asn1:"optional"`
}

func ParseCRL(der []byte) (*CRL, error) {
	var cl certificateList
	if rest, err := asn1.Unmarshal(der, &cl); err != nil || len(rest) > 0 {
		return nil, errors.New("malformed certificate revocation list")
	}
	var tbs tbsCertList
	if rest, err := asn1.Unmarshal(cl.TBS.FullBytes, &tbs); err != nil || len(rest) > 0 {
		return nil, errors.New("malformed certificate revocation list contents")
	}
	if tbs.Version > 1 {
		return nil, errors.New("unsupported certificate revocation list version")
	}
	l := &CRL{RawIssuer: tbs.Issuer.FullBytes, ThisUpdate: tbs.ThisUpdate, NextUpdate: tbs.NextUpdate, Version: tbs.Version + 1, revoked: map[string]bool{},
		tbs: cl.TBS.FullBytes, sigAlg: signatureAlgorithm(cl.SignatureAlgorithm), sig: cl.Signature.RightAlign()}
	var name pkix.RDNSequence
	if _, err := asn1.Unmarshal(tbs.Issuer.FullBytes, &name); err == nil {
		var n pkix.Name
		n.FillFromRDNSequence(&name)
		l.Issuer = n.String()
	}
	for _, e := range tbs.RevokedCertificates {
		if e.SerialNumber != nil {
			l.revoked[e.SerialNumber.Text(16)] = true
		}
	}
	return l, nil
}

func (l *CRL) Revoked() int { return len(l.revoked) }

func (l *CRL) Lists(serial *big.Int) bool { return serial != nil && l.revoked[serial.Text(16)] }

func (l *CRL) CheckSignatureFrom(issuer *x509.Certificate) error {
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("issuer may not sign revocation lists")
	}
	if l.sigAlg == x509.UnknownSignatureAlgorithm {
		return errors.New("unsupported revocation list signature algorithm")
	}
	return issuer.CheckSignature(l.sigAlg, l.tbs, l.sig)
}

func ParseCRLs(data []byte) ([]*CRL, error) {
	var out []*CRL
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "X509 CRL" {
			continue
		}
		l, err := ParseCRL(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if len(out) > 0 {
		return out, nil
	}
	l, err := ParseCRL(data)
	if err != nil {
		return nil, err
	}
	return []*CRL{l}, nil
}
