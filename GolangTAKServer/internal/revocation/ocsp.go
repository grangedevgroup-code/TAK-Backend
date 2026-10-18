package revocation

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidBasicOCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidRSAPSS    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

var sigAlgs = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.5":  x509.SHA1WithRSA,
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.10045.4.1":     x509.ECDSAWithSHA1,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	"1.3.101.112":           x509.PureEd25519,
}

type certID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type ocspSingleRequest struct {
	Cert certID
}

type tbsRequest struct {
	Version     int `asn1:"explicit,tag:0,default:0,optional"`
	RequestList []ocspSingleRequest
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspResponse struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type basicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Version     int `asn1:"optional,default:0,explicit,tag:0"`
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []singleResponse
	Extensions  []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponse struct {
	CertID     certID
	Status     asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

type Status int

const (
	Good Status = iota
	Revoked
	Unknown
)

type OCSPResult struct {
	Status     Status
	ThisUpdate time.Time
	NextUpdate time.Time
	RevokedAt  time.Time
}

func publicKeyBits(c *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, err
	}
	return spki.PublicKey.RightAlign(), nil
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, true
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

func makeCertID(h crypto.Hash, oid asn1.ObjectIdentifier, cert, issuer *x509.Certificate) (certID, error) {
	key, err := publicKeyBits(issuer)
	if err != nil {
		return certID{}, err
	}
	nh := h.New()
	nh.Write(issuer.RawSubject)
	kh := h.New()
	kh.Write(key)
	return certID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}, IssuerNameHash: nh.Sum(nil), IssuerKeyHash: kh.Sum(nil), SerialNumber: cert.SerialNumber}, nil
}

func CreateRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	id, err := makeCertID(crypto.SHA1, oidSHA1, cert, issuer)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ocspRequest{TBSRequest: tbsRequest{RequestList: []ocspSingleRequest{{Cert: id}}}})
}

func ParseRequest(b []byte) (serial *big.Int, nameHash, keyHash []byte, hashOID asn1.ObjectIdentifier, err error) {
	var req ocspRequest
	rest, err := asn1.Unmarshal(b, &req)
	if err != nil || len(rest) > 0 || len(req.TBSRequest.RequestList) == 0 {
		return nil, nil, nil, nil, errors.New("ocsp: malformed request")
	}
	id := req.TBSRequest.RequestList[0].Cert
	return id.SerialNumber, id.IssuerNameHash, id.IssuerKeyHash, id.HashAlgorithm.Algorithm, nil
}

func signatureAlgorithm(ai pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	if ai.Algorithm.Equal(oidRSAPSS) {
		var params struct {
			Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional"`
		}
		asn1.Unmarshal(ai.Parameters.FullBytes, &params)
		switch {
		case params.Hash.Algorithm.Equal(oidSHA256):
			return x509.SHA256WithRSAPSS
		case params.Hash.Algorithm.Equal(oidSHA384):
			return x509.SHA384WithRSAPSS
		case params.Hash.Algorithm.Equal(oidSHA512):
			return x509.SHA512WithRSAPSS
		}
		return x509.UnknownSignatureAlgorithm
	}
	return sigAlgs[ai.Algorithm.String()]
}

func ParseResponse(b []byte, cert, issuer *x509.Certificate, now time.Time) (OCSPResult, error) {
	var resp ocspResponse
	rest, err := asn1.Unmarshal(b, &resp)
	if err != nil || len(rest) > 0 {
		return OCSPResult{}, errors.New("ocsp: malformed response")
	}
	if resp.Status != 0 {
		return OCSPResult{}, fmt.Errorf("ocsp: responder returned status %d", resp.Status)
	}
	if !resp.Response.ResponseType.Equal(oidBasicOCSP) {
		return OCSPResult{}, errors.New("ocsp: unsupported response type")
	}
	var basic basicResponse
	if rest, err := asn1.Unmarshal(resp.Response.Response, &basic); err != nil || len(rest) > 0 {
		return OCSPResult{}, errors.New("ocsp: malformed basic response")
	}
	var data responseData
	if rest, err := asn1.Unmarshal(basic.TBSResponseData.FullBytes, &data); err != nil || len(rest) > 0 {
		return OCSPResult{}, errors.New("ocsp: malformed response data")
	}
	signer := issuer
	for _, raw := range basic.Certificates {
		rc, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		if bytes.Equal(rc.Raw, issuer.Raw) {
			signer = issuer
			break
		}
		if rc.CheckSignatureFrom(issuer) != nil || now.Before(rc.NotBefore) || now.After(rc.NotAfter) {
			continue
		}
		delegated := false
		for _, u := range rc.ExtKeyUsage {
			if u == x509.ExtKeyUsageOCSPSigning {
				delegated = true
			}
		}
		if delegated {
			signer = rc
			break
		}
	}
	alg := signatureAlgorithm(basic.SignatureAlgorithm)
	if alg == x509.UnknownSignatureAlgorithm {
		return OCSPResult{}, errors.New("ocsp: unsupported signature algorithm")
	}
	if err := signer.CheckSignature(alg, basic.TBSResponseData.FullBytes, basic.Signature.RightAlign()); err != nil {
		return OCSPResult{}, fmt.Errorf("ocsp: bad response signature: %w", err)
	}
	for _, sr := range data.Responses {
		if sr.CertID.SerialNumber == nil || sr.CertID.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		h, ok := hashFor(sr.CertID.HashAlgorithm.Algorithm)
		if !ok {
			continue
		}
		want, err := makeCertID(h, sr.CertID.HashAlgorithm.Algorithm, cert, issuer)
		if err != nil || !bytes.Equal(want.IssuerNameHash, sr.CertID.IssuerNameHash) || !bytes.Equal(want.IssuerKeyHash, sr.CertID.IssuerKeyHash) {
			continue
		}
		const skew = 5 * time.Minute
		if sr.ThisUpdate.After(now.Add(skew)) {
			return OCSPResult{}, errors.New("ocsp: response is not yet valid")
		}
		if !sr.NextUpdate.IsZero() && sr.NextUpdate.Before(now.Add(-skew)) {
			return OCSPResult{}, errors.New("ocsp: response has expired")
		}
		res := OCSPResult{ThisUpdate: sr.ThisUpdate, NextUpdate: sr.NextUpdate}
		switch sr.Status.Tag {
		case 0:
			res.Status = Good
		case 1:
			res.Status = Revoked
			var ri revokedInfo
			full := append([]byte{0x30}, asn1Length(len(sr.Status.Bytes))...)
			if _, err := asn1.Unmarshal(append(full, sr.Status.Bytes...), &ri); err == nil {
				res.RevokedAt = ri.RevocationTime
			}
		default:
			res.Status = Unknown
		}
		return res, nil
	}
	return OCSPResult{}, errors.New("ocsp: response does not cover the certificate")
}

func asn1Length(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

type ResponseTemplate struct {
	Status     Status
	ThisUpdate time.Time
	NextUpdate time.Time
	RevokedAt  time.Time
}

func CreateResponse(issuer, responder *x509.Certificate, key crypto.Signer, serial *big.Int, nameHash, keyHash []byte, hashOID asn1.ObjectIdentifier, t ResponseTemplate) ([]byte, error) {
	status := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}
	switch t.Status {
	case Revoked:
		inner, err := asn1.Marshal(revokedInfo{RevocationTime: t.RevokedAt.UTC()})
		if err != nil {
			return nil, err
		}
		var rv asn1.RawValue
		asn1.Unmarshal(inner, &rv)
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: rv.Bytes}
	case Unknown:
		status = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2}
	}
	keyBits, err := publicKeyBits(responder)
	if err != nil {
		return nil, err
	}
	kh := sha1.Sum(keyBits)
	rid, err := asn1.Marshal(kh[:])
	if err != nil {
		return nil, err
	}
	sr := singleResponse{
		CertID:     certID{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue}, IssuerNameHash: nameHash, IssuerKeyHash: keyHash, SerialNumber: serial},
		Status:     status,
		ThisUpdate: t.ThisUpdate.UTC(),
		NextUpdate: t.NextUpdate.UTC(),
	}
	tbs, err := asn1.Marshal(responseData{ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: rid}, ProducedAt: time.Now().UTC().Truncate(time.Second), Responses: []singleResponse{sr}})
	if err != nil {
		return nil, err
	}
	h := crypto.SHA256
	d := h.New()
	d.Write(tbs)
	var sigAlg asn1.ObjectIdentifier
	var opts crypto.SignerOpts = h
	digest := d.Sum(nil)
	switch responder.PublicKeyAlgorithm {
	case x509.RSA:
		sigAlg = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	case x509.ECDSA:
		sigAlg = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	case x509.Ed25519:
		sigAlg = asn1.ObjectIdentifier{1, 3, 101, 112}
		digest, opts = tbs, crypto.Hash(0)
	default:
		return nil, errors.New("ocsp: unsupported responder key")
	}
	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}
	br := basicResponse{TBSResponseData: asn1.RawValue{FullBytes: tbs}, SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigAlg}, Signature: asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}}
	if !bytes.Equal(responder.Raw, issuer.Raw) {
		br.Certificates = []asn1.RawValue{{FullBytes: responder.Raw}}
	}
	basic, err := asn1.Marshal(br)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ocspResponse{Status: 0, Response: responseBytes{ResponseType: oidBasicOCSP, Response: basic}})
}
