package quic

import "testing"

func FuzzParsePacket(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x40, 0x20})
	f.Add([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add(appendAck(appendCrypto(nil, 5, []byte("hello")), []ackRange{{3, 9}, {0, 1}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseHeader(b, cidLen)
		parseFrames(b)
		decodeTransportParams(b)
		longIDs(b)
		readVarint(b)
	})
}
