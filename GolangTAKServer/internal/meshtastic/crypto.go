package meshtastic

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	PortText      = 1
	PortPosition  = 3
	PortNodeInfo  = 4
	PortRouting   = 5
	PortWaypoint  = 8
	PortTelemetry = 67
	PortATAK      = 72
	PortMapReport = 73
	Broadcast     = 0xffffffff
)

var DefaultKey = []byte{0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}

func ExpandKey(psk []byte) ([]byte, error) {
	switch {
	case len(psk) == 0:
		return nil, nil
	case len(psk) == 1:
		if psk[0] == 0 {
			return nil, nil
		}
		k := append([]byte(nil), DefaultKey...)
		k[len(k)-1] += psk[0] - 1
		return k, nil
	case len(psk) <= 16:
		k := make([]byte, 16)
		copy(k, psk)
		return k, nil
	case len(psk) <= 32:
		k := make([]byte, 32)
		copy(k, psk)
		return k, nil
	}
	return nil, errors.New("meshtastic: channel key longer than 32 bytes")
}

func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ExpandKey([]byte{1})
	}
	if strings.EqualFold(s, "none") {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("meshtastic: channel key is not base64: %w", err)
		}
	}
	return ExpandKey(raw)
}

func xorHash(b []byte) byte {
	var h byte
	for _, c := range b {
		h ^= c
	}
	return h
}

func ChannelHash(name string, key []byte) uint32 {
	return uint32(xorHash([]byte(name)) ^ xorHash(key))
}

func Crypt(key []byte, packetID, from uint32, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return append([]byte(nil), data...), nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	binary.LittleEndian.PutUint64(nonce, uint64(packetID))
	binary.LittleEndian.PutUint32(nonce[8:], from)
	out := make([]byte, len(data))
	cipher.NewCTR(block, nonce).XORKeyStream(out, data)
	return out, nil
}

func NodeID(n uint32) string { return fmt.Sprintf("!%08x", n) }

func ParseNodeID(s string) (uint32, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "!")
	if len(s) == 0 || len(s) > 8 {
		return 0, false
	}
	var v uint32
	for _, c := range s {
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

var teams = []string{"", "White", "Yellow", "Orange", "Magenta", "Red", "Maroon", "Purple", "Dark Blue", "Blue", "Cyan", "Teal", "Green", "Dark Green", "Brown"}

var roles = []string{"", "Team Member", "Team Lead", "HQ", "Sniper", "Medic", "Forward Observer", "RTO", "K9"}

func TeamName(n uint32) string {
	if int(n) < len(teams) && n > 0 {
		return teams[n]
	}
	return "Cyan"
}

func RoleName(n uint32) string {
	if int(n) < len(roles) && n > 0 {
		return roles[n]
	}
	return "Team Member"
}

func TeamNumber(name string) uint32 {
	for i, t := range teams {
		if i > 0 && strings.EqualFold(t, name) {
			return uint32(i)
		}
	}
	return 10
}

func RoleNumber(name string) uint32 {
	for i, r := range roles {
		if i > 0 && strings.EqualFold(r, name) {
			return uint32(i)
		}
	}
	return 1
}
