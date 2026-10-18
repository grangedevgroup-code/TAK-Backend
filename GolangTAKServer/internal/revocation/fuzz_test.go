package revocation

import (
	"testing"
	"time"
)

func FuzzParseOCSPAndCRL(f *testing.F) {
	ca := newCA(&testing.T{}, "CA")
	leaf := ca.issue(&testing.T{}, "leaf", 7, "")
	f.Add([]byte{0x30, 0x03, 0x0a, 0x01, 0x00})
	f.Add(ca.crlV1(&testing.T{}, 7))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseResponse(b, leaf, ca.cert, time.Now())
		if l, err := ParseCRL(b); err == nil {
			l.CheckSignatureFrom(ca.cert)
			l.Lists(leaf.SerialNumber)
		}
		ParseCRLs(b)
	})
}
