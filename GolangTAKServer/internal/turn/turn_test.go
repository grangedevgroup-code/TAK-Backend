package turn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type testClient struct {
	t    *testing.T
	conn *net.UDPConn
	srv  *net.UDPAddr
	key  []byte
	user string
	nonc []byte
}

func (c *testClient) roundTrip(b *builder, method uint16, auth bool) *message {
	c.t.Helper()
	if auth {
		b.add(attrUsername, []byte(c.user))
		b.add(attrRealm, []byte("test"))
		b.add(attrNonce, c.nonc)
		b.integrity(c.key)
	}
	c.conn.WriteToUDP(b.fingerprint(), c.srv)
	buf := make([]byte, 2048)
	for {
		c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.t.Fatalf("no reply: %v", err)
		}
		m, err := parse(append([]byte(nil), buf[:n]...))
		if err == nil && m.method == method && m.class != classIndication {
			return m
		}
	}
}

func txid() [12]byte {
	var t [12]byte
	rand.Read(t[:])
	return t
}

func TestTURNRelay(t *testing.T) {
	secret := []byte("turn-secret")
	srv, err := Listen("127.0.0.1:0", Config{Realm: "test", Secret: secret, RelayIP: net.IPv4(127, 0, 0, 1), PortMin: 49300, PortMax: 49340, AllowPeer: func(net.IP) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer conn.Close()
	user, pass := Credentials(secret, "alice", time.Hour)
	c := &testClient{t: t, conn: conn, srv: srv.Addr(), user: user, key: longTermKey(user, "test", pass)}

	m := c.roundTrip(newBuilder(methodBinding, classRequest, txid()), methodBinding, false)
	if v, ok := m.get(attrXorMappedAddress); !ok || m.class != classSuccess {
		t.Fatal("binding failed")
	} else if a, _ := parseXorAddr(v, m.txid); a.Port != conn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("mapped %v", a)
	}

	m = c.roundTrip(newBuilder(methodAllocate, classRequest, txid()).add(attrRequestedTransport, []byte{17, 0, 0, 0}), methodAllocate, false)
	if m.class != classError {
		t.Fatal("allocation without credentials succeeded")
	}
	c.nonc, _ = m.get(attrNonce)
	m = c.roundTrip(newBuilder(methodAllocate, classRequest, txid()).add(attrRequestedTransport, []byte{17, 0, 0, 0}), methodAllocate, true)
	if m.class != classSuccess || !m.checkIntegrity(c.key) {
		v, _ := m.get(attrErrorCode)
		t.Fatalf("allocate: class %x %q", m.class, v)
	}
	rv, _ := m.get(attrXorRelayedAddress)
	relayed, _ := parseXorAddr(rv, m.txid)

	bad := &testClient{t: t, conn: conn, srv: srv.Addr(), user: user, key: longTermKey(user, "test", "wrong"), nonc: c.nonc}
	if m := bad.roundTrip(newBuilder(methodRefresh, classRequest, txid()), methodRefresh, true); m.class != classError {
		t.Fatal("wrong password accepted")
	}

	peer, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer peer.Close()
	pa := peer.LocalAddr().(*net.UDPAddr)

	peer.WriteToUDP([]byte("too early"), relayed)
	time.Sleep(200 * time.Millisecond)
	tid := txid()
	m = c.roundTrip(newBuilder(methodCreatePermission, classRequest, tid).add(attrXorPeerAddress, xorAddr(pa, tid)), methodCreatePermission, true)
	if m.class != classSuccess {
		t.Fatal("create permission failed")
	}

	tid = txid()
	ind := newBuilder(methodSend, classIndication, tid).add(attrXorPeerAddress, xorAddr(pa, tid)).add(attrData, []byte("hello peer"))
	conn.WriteToUDP(ind.fingerprint(), srv.Addr())
	buf := make([]byte, 2048)
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := peer.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "hello peer" || from.Port != relayed.Port {
		t.Fatalf("peer got %q from %v: %v", buf[:n], from, err)
	}

	peer.WriteToUDP([]byte("hello client"), relayed)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	dm, err := parse(buf[:n])
	if err != nil || dm.method != methodData || dm.class != classIndication {
		t.Fatalf("expected a data indication, got %x", buf[:min(n, 4)])
	}
	if d, _ := dm.get(attrData); string(d) != "hello client" {
		t.Fatalf("data %q", d)
	}

	tid = txid()
	ch := []byte{0x40, 0x01, 0, 0}
	m = c.roundTrip(newBuilder(methodChannelBind, classRequest, tid).add(attrChannelNumber, ch).add(attrXorPeerAddress, xorAddr(pa, tid)), methodChannelBind, true)
	if m.class != classSuccess {
		t.Fatal("channel bind failed")
	}
	frame := []byte{0x40, 0x01, 0, 5, 'h', 'e', 'l', 'l', 'o', 0, 0, 0}
	conn.WriteToUDP(frame, srv.Addr())
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _, err := peer.ReadFromUDP(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("channel data to peer: %q %v", buf[:n], err)
	}
	peer.WriteToUDP([]byte("back"), relayed)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = conn.ReadFromUDP(buf)
	if err != nil || n != 8 || binary.BigEndian.Uint16(buf[0:2]) != 0x4001 || !bytes.Equal(buf[4:8], []byte("back")) {
		t.Fatalf("channel data to client: %x %v", buf[:n], err)
	}

	m = c.roundTrip(newBuilder(methodRefresh, classRequest, txid()).add(attrLifetime, []byte{0, 0, 0, 0}), methodRefresh, true)
	if m.class != classSuccess || srv.Allocations() != 0 {
		t.Fatalf("refresh to zero: class %x allocations %d", m.class, srv.Allocations())
	}

	expiredUser := "1:alice"
	if _, err := srv.password(expiredUser); err == nil {
		t.Fatal("expired credentials accepted")
	}
}

func TestDefaultPeerPolicy(t *testing.T) {
	s := &Server{}
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "::1"} {
		if s.peerAllowed(net.ParseIP(ip)) {
			t.Fatalf("%s allowed", ip)
		}
	}
	for _, ip := range []string{"192.168.1.20", "10.0.0.5", "8.8.8.8", "100.64.1.1"} {
		if !s.peerAllowed(net.ParseIP(ip)) {
			t.Fatalf("%s refused", ip)
		}
	}
}
