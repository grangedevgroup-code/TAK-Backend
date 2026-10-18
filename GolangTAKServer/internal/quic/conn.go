package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

var (
	ErrClosed       = errors.New("quic: connection closed")
	errStreamLimit  = errors.New("quic: stream limit exceeded")
	errFlowControl  = errors.New("quic: flow control violated")
	errHandshakeTLS = errors.New("quic: TLS handshake failed")
)

const (
	spInitial = iota
	spHandshake
	spApp
)

const (
	recvWindow     = 4 << 20
	connRecvWindow = 16 << 20
	maxSendBuffer  = 8 << 20
	initialCwnd    = 10 * maxDatagram
	minCwnd        = 2 * maxDatagram
)

type rangeSet []ackRange

func (rs *rangeSet) add(lo, hi uint64) {
	s := *rs
	i := sort.Search(len(s), func(i int) bool { return s[i].hi+1 >= lo })
	j := i
	for j < len(s) && s[j].lo <= hi+1 {
		if s[j].lo < lo {
			lo = s[j].lo
		}
		if s[j].hi > hi {
			hi = s[j].hi
		}
		j++
	}
	s = append(s[:i], append([]ackRange{{lo, hi}}, s[j:]...)...)
	*rs = s
}

func (rs rangeSet) contains(v uint64) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= v })
	return i < len(rs) && rs[i].lo <= v
}

func (rs rangeSet) descending(limit int) []ackRange {
	var out []ackRange
	for i := len(rs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, rs[i])
	}
	return out
}

type cryptoStream struct {
	out     []byte
	sent    uint64
	lost    []ackRange
	inNext  uint64
	inParts map[uint64][]byte
}

type sentPacket struct {
	pn           uint64
	time         time.Time
	size         int
	ackEliciting bool
	crypto       []ackRange
	stream       []ackRange
	fin          bool
	hsDone       bool
	maxData      bool
	maxStream    bool
}

type space struct {
	rx, tx       *keys
	nextPN       uint64
	largestRecv  int64
	recvd        rangeSet
	ackNeeded    bool
	sent         map[uint64]*sentPacket
	largestAcked int64
	crypto       cryptoStream
	discarded    bool
	lastAckElic  time.Time
}

func newSpace() *space {
	return &space{largestRecv: -1, largestAcked: -1, sent: map[uint64]*sentPacket{}, crypto: cryptoStream{inParts: map[uint64][]byte{}}}
}

type Conn struct {
	mu        sync.Mutex
	client    bool
	pc        net.PacketConn
	addr      net.Addr
	tls       *tls.QUICConn
	state     tls.ConnectionState
	spaces    [3]*space
	ourCID    []byte
	peerCID   []byte
	origDCID  []byte
	firstPeer bool
	params    transportParams
	peer      transportParams
	peerSet   bool
	in        chan []byte
	wake      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	closing   bool
	sentClose bool
	idle      time.Duration
	lastRecv  time.Time
	lastSend  time.Time
	validated bool
	rxBytes   int
	txBytes   int

	handshakeDone bool
	hsDonePending bool
	established   chan struct{}
	estOnce       sync.Once

	keyPhase bool
	nextRx   *keys

	srtt, rttvar, latestRTT time.Duration
	hasRTT                  bool
	ptoCount                int
	cwnd, inFlight          int
	ssthresh                int
	recoveryStart           time.Time

	rxMaxData     uint64
	rxConsumed    uint64
	rxReceived    uint64
	txMaxData     uint64
	txSentData    uint64
	maxDataUpdate bool
	pathResponse  [][8]byte

	stream      *Stream
	streamCount uint64
	onStream    func(*Stream)
}

func randomCID() []byte {
	b := make([]byte, cidLen)
	rand.Read(b)
	return b
}

func newConn(client bool, pc net.PacketConn, addr net.Addr, idle time.Duration) *Conn {
	c := &Conn{client: client, pc: pc, addr: addr, in: make(chan []byte, 256), wake: make(chan struct{}, 1), done: make(chan struct{}),
		idle: idle, established: make(chan struct{}), cwnd: initialCwnd, ssthresh: 1 << 30, rxMaxData: connRecvWindow, lastRecv: time.Now()}
	for i := range c.spaces {
		c.spaces[i] = newSpace()
	}
	return c
}

func levelSpace(l tls.QUICEncryptionLevel) int {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return spInitial
	case tls.QUICEncryptionLevelHandshake:
		return spHandshake
	case tls.QUICEncryptionLevelApplication:
		return spApp
	}
	return -1
}

func spaceLevel(sp int) tls.QUICEncryptionLevel {
	switch sp {
	case spInitial:
		return tls.QUICEncryptionLevelInitial
	case spHandshake:
		return tls.QUICEncryptionLevelHandshake
	}
	return tls.QUICEncryptionLevelApplication
}

func (c *Conn) ourTransportParams() transportParams {
	p := transportParams{maxIdleTimeoutMs: uint64(c.idle / time.Millisecond), initialMaxData: connRecvWindow, maxStreamDataBL: recvWindow,
		maxStreamDataBR: recvWindow, maxStreamDataUni: 0, maxStreamsBidi: 1, maxStreamsUni: 0, activeCIDLimit: 2, disableMigration: true,
		maxUDPPayload: 1452, initialSCID: c.ourCID}
	if !c.client {
		p.origDCID = c.origDCID
	}
	return p
}

func (c *Conn) startTLS(cfg *tls.Config) error {
	qc := &tls.QUICConfig{TLSConfig: cfg}
	if c.client {
		c.tls = tls.QUICClient(qc)
	} else {
		c.tls = tls.QUICServer(qc)
	}
	c.params = c.ourTransportParams()
	c.tls.SetTransportParameters(c.params.encode())
	if err := c.tls.Start(context.Background()); err != nil {
		return err
	}
	return c.handleTLSEvents()
}

func (c *Conn) handleTLSEvents() error {
	for {
		e := c.tls.NextEvent()
		switch e.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
			sp := levelSpace(e.Level)
			if sp < 0 {
				continue
			}
			k, err := newKeys(e.Suite, append([]byte(nil), e.Data...))
			if err != nil {
				return err
			}
			if e.Kind == tls.QUICSetReadSecret {
				c.spaces[sp].rx = k
				if sp == spApp {
					c.nextRx, _ = k.next()
				}
			} else {
				c.spaces[sp].tx = k
			}
		case tls.QUICWriteData:
			sp := levelSpace(e.Level)
			if sp >= 0 {
				c.spaces[sp].crypto.out = append(c.spaces[sp].crypto.out, e.Data...)
			}
		case tls.QUICTransportParameters:
			p, err := decodeTransportParams(e.Data)
			if err != nil {
				return err
			}
			c.peer, c.peerSet = p, true
			if p.initialMaxData > c.txMaxData {
				c.txMaxData = p.initialMaxData
			}
			if p.maxIdleTimeoutMs > 0 && (c.idle == 0 || time.Duration(p.maxIdleTimeoutMs)*time.Millisecond < c.idle) {
				c.idle = time.Duration(p.maxIdleTimeoutMs) * time.Millisecond
			}
		case tls.QUICTransportParametersRequired:
			c.tls.SetTransportParameters(c.params.encode())
		case tls.QUICHandshakeDone:
			c.handshakeDone = true
			c.state = c.tls.ConnectionState()
			if !c.client {
				c.hsDonePending = true
				c.dropSpace(spInitial)
				c.dropSpace(spHandshake)
			}
			c.estOnce.Do(func() { close(c.established) })
		default:
			if e.Err != nil {
				return e.Err
			}
		}
	}
}

func (c *Conn) dropSpace(sp int) {
	s := c.spaces[sp]
	if s.discarded {
		return
	}
	for _, p := range s.sent {
		if p.ackEliciting {
			c.inFlight -= p.size
		}
	}
	s.sent = map[uint64]*sentPacket{}
	s.discarded = true
	s.ackNeeded = false
}

func (c *Conn) handleDatagram(d []byte) {
	c.rxBytes += len(d)
	for len(d) > 0 {
		h, err := parseHeader(d, cidLen)
		if err != nil {
			return
		}
		pkt := d[:h.end]
		d = d[h.end:]
		if h.typ != ptShort && h.version != version1 {
			continue
		}
		sp := spApp
		switch h.typ {
		case ptInitial:
			sp = spInitial
		case ptHandshake:
			sp = spHandshake
		case ptZeroRTT, ptRetry:
			continue
		}
		s := c.spaces[sp]
		if s.rx == nil || s.discarded {
			continue
		}
		pn, payload, keyPhase, err := unprotectTry(s.rx, pkt, h, s.largestRecv)
		if err != nil && sp == spApp && c.nextRx != nil {
			var pn2 uint64
			var p2 []byte
			pn2, p2, keyPhase, err = unprotectTry(c.nextRx, pkt, h, s.largestRecv)
			if err == nil && keyPhase != c.keyPhase {
				c.rotateKeys()
				pn, payload = pn2, p2
			}
		}
		if err != nil {
			continue
		}
		if s.recvd.contains(pn) {
			continue
		}
		if c.client && !c.firstPeer && h.typ != ptShort {
			c.peerCID = append([]byte(nil), h.scid...)
			c.firstPeer = true
		}
		if sp == spHandshake && !c.client {
			c.validated = true
			c.dropSpace(spInitial)
		}
		frames, err := parseFrames(payload)
		if err != nil {
			c.fail(err)
			return
		}
		s.recvd.add(pn, pn)
		if int64(pn) > s.largestRecv {
			s.largestRecv = int64(pn)
		}
		if len(s.recvd) > 64 {
			s.recvd = s.recvd[len(s.recvd)-64:]
		}
		if ackEliciting(frames) {
			s.ackNeeded = true
		}
		c.lastRecv = time.Now()
		for _, f := range frames {
			if err := c.handleFrame(sp, f); err != nil {
				c.fail(err)
				return
			}
		}
	}
}

func (c *Conn) rotateKeys() {
	s := c.spaces[spApp]
	s.rx = c.nextRx
	c.nextRx, _ = s.rx.next()
	if nt, err := s.tx.next(); err == nil {
		s.tx = nt
	}
	c.keyPhase = !c.keyPhase
}

func (c *Conn) handleFrame(sp int, f frame) error {
	s := c.spaces[sp]
	switch f.typ {
	case frAck, frAckECN:
		c.onAck(sp, f.ackRanges)
	case frCrypto:
		cs := &s.crypto
		end := f.offset + uint64(len(f.data))
		if end <= cs.inNext {
			return nil
		}
		if end-cs.inNext > 1<<20 {
			return errFlowControl
		}
		cs.inParts[f.offset] = append([]byte(nil), f.data...)
		for {
			progressed := false
			for off, data := range cs.inParts {
				if off <= cs.inNext && off+uint64(len(data)) > cs.inNext {
					chunk := data[cs.inNext-off:]
					delete(cs.inParts, off)
					cs.inNext += uint64(len(chunk))
					if err := c.tls.HandleData(spaceLevel(sp), chunk); err != nil {
						return err
					}
					progressed = true
				} else if off+uint64(len(data)) <= cs.inNext {
					delete(cs.inParts, off)
				}
			}
			if !progressed {
				break
			}
		}
		return c.handleTLSEvents()
	case frStream:
		if sp != spApp {
			return errFrame
		}
		st, err := c.streamFor(f.streamID)
		if err != nil || st == nil {
			return err
		}
		return st.receive(f.offset, f.data, f.fin)
	case frMaxData:
		if f.maxValue > c.txMaxData {
			c.txMaxData = f.maxValue
		}
	case frMaxStreamData:
		if c.stream != nil && c.stream.id == f.streamID && f.maxValue > c.stream.peerMax {
			c.stream.peerMax = f.maxValue
		}
	case frResetStream:
		if c.stream != nil && c.stream.id == f.streamID {
			c.stream.resetErr = io.ErrUnexpectedEOF
			c.stream.signal()
		}
	case frStopSending:
		if c.stream != nil && c.stream.id == f.streamID {
			c.stream.writeErr = io.ErrClosedPipe
			c.stream.signal()
		}
	case frPathChallenge:
		c.pathResponse = append(c.pathResponse, f.pathData)
	case frConnClose, frConnCloseApp:
		c.sentClose = true
		c.terminate(ErrClosed)
	case frHandshakeDone:
		if c.client {
			c.dropSpace(spInitial)
			c.dropSpace(spHandshake)
		}
	}
	return nil
}

func (c *Conn) streamFor(id uint64) (*Stream, error) {
	if c.stream != nil && c.stream.id == id {
		return c.stream, nil
	}
	if c.client {
		return nil, nil
	}
	if id%4 != 0 {
		return nil, errStreamLimit
	}
	if c.stream != nil || id/4 >= c.params.maxStreamsBidi {
		return nil, errStreamLimit
	}
	c.stream = newStream(c, id)
	c.stream.peerMax = c.peer.maxStreamDataBL
	if c.onStream != nil {
		c.onStream(c.stream)
	}
	return c.stream, nil
}

func (c *Conn) onAck(sp int, ranges []ackRange) {
	s := c.spaces[sp]
	now := time.Now()
	var newlyAcked []*sentPacket
	largest := int64(-1)
	for _, r := range ranges {
		if int64(r.hi) > largest {
			largest = int64(r.hi)
		}
		for pn, p := range s.sent {
			if pn >= r.lo && pn <= r.hi {
				newlyAcked = append(newlyAcked, p)
				delete(s.sent, pn)
			}
		}
	}
	if len(newlyAcked) == 0 {
		return
	}
	if largest > s.largestAcked {
		s.largestAcked = largest
	}
	for _, p := range newlyAcked {
		if int64(p.pn) == largest && p.ackEliciting {
			c.updateRTT(now.Sub(p.time))
		}
		if p.ackEliciting {
			c.inFlight -= p.size
			if c.cwnd < c.ssthresh {
				c.cwnd += p.size
			} else {
				c.cwnd += maxDatagram * p.size / c.cwnd
			}
		}
		if sp == spApp && c.stream != nil {
			for _, r := range p.stream {
				c.stream.acked(r)
			}
			if p.fin {
				c.stream.finAcked = true
			}
		}
	}
	c.ptoCount = 0
	c.detectLoss(sp, now)
}

func (c *Conn) updateRTT(sample time.Duration) {
	c.latestRTT = sample
	if !c.hasRTT {
		c.srtt, c.rttvar, c.hasRTT = sample, sample/2, true
		return
	}
	d := c.srtt - sample
	if d < 0 {
		d = -d
	}
	c.rttvar = (3*c.rttvar + d) / 4
	c.srtt = (7*c.srtt + sample) / 8
}

func (c *Conn) lossDelay() time.Duration {
	r := max(c.srtt, c.latestRTT)
	if !c.hasRTT {
		r = 333 * time.Millisecond
	}
	return max(r*9/8, time.Millisecond)
}

func (c *Conn) detectLoss(sp int, now time.Time) {
	s := c.spaces[sp]
	if s.largestAcked < 0 {
		return
	}
	lost := false
	for pn, p := range s.sent {
		if int64(pn) > s.largestAcked {
			continue
		}
		if s.largestAcked-int64(pn) >= 3 || now.Sub(p.time) > c.lossDelay() {
			c.requeue(sp, p)
			delete(s.sent, pn)
			if p.ackEliciting {
				c.inFlight -= p.size
				lost = true
			}
		}
	}
	if lost && now.Sub(c.recoveryStart) > c.srtt {
		c.recoveryStart = now
		c.ssthresh = max(c.cwnd/2, minCwnd)
		c.cwnd = c.ssthresh
	}
}

func (c *Conn) requeue(sp int, p *sentPacket) {
	s := c.spaces[sp]
	s.crypto.lost = append(s.crypto.lost, p.crypto...)
	if sp == spApp {
		if c.stream != nil {
			for _, r := range p.stream {
				c.stream.lost = append(c.stream.lost, r)
			}
			if p.fin && !c.stream.finAcked {
				c.stream.finSent = false
			}
		}
		if p.hsDone {
			c.hsDonePending = true
		}
		if p.maxData {
			c.maxDataUpdate = true
		}
		if p.maxStream && c.stream != nil {
			c.stream.maxUpdate = true
		}
	}
}

func (c *Conn) pto() time.Duration {
	srtt, rttvar := c.srtt, c.rttvar
	if !c.hasRTT {
		srtt, rttvar = 333*time.Millisecond, 166*time.Millisecond
	}
	d := srtt + max(4*rttvar, time.Millisecond) + 25*time.Millisecond
	return d << min(c.ptoCount, 6)
}

func (c *Conn) nextTimer() time.Time {
	var t time.Time
	set := func(x time.Time) {
		if !x.IsZero() && (t.IsZero() || x.Before(t)) {
			t = x
		}
	}
	for _, s := range c.spaces {
		if len(s.sent) > 0 && !s.lastAckElic.IsZero() {
			set(s.lastAckElic.Add(c.pto()))
		}
	}
	if c.idle > 0 {
		set(c.lastRecv.Add(c.idle))
		if c.handshakeDone {
			set(c.lastSend.Add(c.idle / 3))
		}
	}
	return t
}

func (c *Conn) onTimer() {
	now := time.Now()
	if c.idle > 0 && now.Sub(c.lastRecv) >= c.idle {
		c.sentClose = true
		c.terminate(errors.New("quic: idle timeout"))
		return
	}
	fired := false
	for sp, s := range c.spaces {
		if len(s.sent) == 0 || s.lastAckElic.IsZero() || now.Before(s.lastAckElic.Add(c.pto())) {
			continue
		}
		for pn, p := range s.sent {
			if p.ackEliciting {
				c.requeue(sp, p)
				c.inFlight -= p.size
				delete(s.sent, pn)
				fired = true
			}
		}
	}
	if fired {
		c.ptoCount++
	}
	if c.handshakeDone && c.idle > 0 && now.Sub(c.lastSend) >= c.idle/3 {
		c.spaces[spApp].ackNeeded = true
		c.pingPending = true
	}
}

func (c *Conn) send(dg []byte) {
	c.txBytes += len(dg)
	c.lastSend = time.Now()
	c.pc.WriteTo(dg, c.addr)
}

func (c *Conn) canSendMore(n int) bool {
	if c.client || c.validated {
		return true
	}
	return c.txBytes+n <= 3*c.rxBytes
}

func (c *Conn) flush() {
	for i := 0; i < 64; i++ {
		var dg []byte
		ackOnly := true
		hasInitial := false
		for sp := spInitial; sp <= spApp; sp++ {
			s := c.spaces[sp]
			if s.tx == nil || s.discarded {
				continue
			}
			room := maxDatagram - len(dg) - 64
			if room < 64 {
				break
			}
			payload, p := c.buildPayload(sp, room)
			if len(payload) == 0 {
				continue
			}
			if p.ackEliciting {
				ackOnly = false
			}
			pn := s.nextPN
			s.nextPN++
			var pkt []byte
			if sp == spApp {
				pkt = seal(s.tx, shortHeader(c.peerCID, pn, c.keyPhase), pn, payload, true)
			} else {
				if sp == spInitial && p.ackEliciting && (c.client || len(dg) == 0) {
					hasInitial = true
				}
				t := ptInitial
				if sp == spHandshake {
					t = ptHandshake
				}
				if hasInitial && sp == spInitial {
					hdrLen := len(longHeader(t, c.peerCID, c.ourCID, nil, pn, len(payload)))
					if need := minInitial - len(dg) - hdrLen - len(payload) - 16; need > 0 {
						payload = append(payload, make([]byte, need)...)
					}
				}
				pkt = seal(s.tx, longHeader(t, c.peerCID, c.ourCID, nil, pn, len(payload)), pn, payload, false)
			}
			p.pn, p.time, p.size = pn, time.Now(), len(pkt)
			if p.ackEliciting {
				s.sent[pn] = p
				s.lastAckElic = p.time
				c.inFlight += p.size
			}
			dg = append(dg, pkt...)
		}
		if len(dg) == 0 {
			return
		}
		if !c.canSendMore(len(dg)) {
			return
		}
		c.send(dg)
		if ackOnly {
			continue
		}
	}
}

func (c *Conn) buildPayload(sp int, room int) ([]byte, *sentPacket) {
	s := c.spaces[sp]
	p := &sentPacket{}
	var b []byte
	if s.ackNeeded && len(s.recvd) > 0 {
		b = appendAck(b, s.recvd.descending(32))
		s.ackNeeded = false
	}
	if c.closing && !c.sentClose && (sp == spApp || !c.handshakeDone) {
		b = appendConnClose(b, 0, "")
		if sp == spApp || c.spaces[spApp].tx == nil {
			c.sentClose = true
		}
		return b, p
	}
	elicit := func() { p.ackEliciting = true }
	congested := c.inFlight >= c.cwnd && c.ptoCount == 0
	cs := &s.crypto
	for len(cs.lost) > 0 && room-len(b) > 32 {
		r := cs.lost[0]
		n := min(int(r.hi-r.lo), room-len(b)-16)
		if n <= 0 {
			break
		}
		b = appendCrypto(b, r.lo, cs.out[r.lo:r.lo+uint64(n)])
		p.crypto = append(p.crypto, ackRange{r.lo, r.lo + uint64(n)})
		if uint64(n) < r.hi-r.lo {
			cs.lost[0].lo += uint64(n)
		} else {
			cs.lost = cs.lost[1:]
		}
		elicit()
	}
	for cs.sent < uint64(len(cs.out)) && room-len(b) > 32 {
		n := min(len(cs.out)-int(cs.sent), room-len(b)-16)
		b = appendCrypto(b, cs.sent, cs.out[cs.sent:cs.sent+uint64(n)])
		p.crypto = append(p.crypto, ackRange{cs.sent, cs.sent + uint64(n)})
		cs.sent += uint64(n)
		elicit()
	}
	if sp == spApp && c.handshakeDone {
		if c.hsDonePending {
			b = appendVarint(b, frHandshakeDone)
			c.hsDonePending = false
			p.hsDone = true
			elicit()
		}
		for len(c.pathResponse) > 0 {
			b = appendVarint(b, frPathResponse)
			b = append(b, c.pathResponse[0][:]...)
			c.pathResponse = c.pathResponse[1:]
			elicit()
		}
		if c.maxDataUpdate {
			c.rxMaxData = c.rxConsumed + connRecvWindow
			b = appendVarint(b, frMaxData)
			b = appendVarint(b, c.rxMaxData)
			c.maxDataUpdate = false
			p.maxData = true
			elicit()
		}
		if st := c.stream; st != nil {
			st.mu.Lock()
			if st.maxUpdate {
				st.rxMax = st.consumed + recvWindow
				b = appendVarint(b, frMaxStreamData)
				b = appendVarint(b, st.id)
				b = appendVarint(b, st.rxMax)
				st.maxUpdate = false
				p.maxStream = true
				elicit()
			}
			for len(st.lost) > 0 && room-len(b) > 32 {
				r := st.lost[0]
				if r.hi <= st.sbase {
					st.lost = st.lost[1:]
					continue
				}
				lo := max(r.lo, st.sbase)
				n := min(int(r.hi-lo), room-len(b)-streamFrameOverhead(st.id, lo, 1400))
				if n <= 0 {
					break
				}
				data := st.sbuf[lo-st.sbase : lo-st.sbase+uint64(n)]
				b = appendStream(b, st.id, lo, data, false)
				p.stream = append(p.stream, ackRange{lo, lo + uint64(n)})
				if lo+uint64(n) < r.hi {
					st.lost[0].lo = lo + uint64(n)
				} else {
					st.lost = st.lost[1:]
				}
				elicit()
			}
			for !congested && room-len(b) > 32 {
				unsent := st.sbase + uint64(len(st.sbuf)) - st.snext
				limit := min(st.peerMax-min(st.peerMax, st.snext), c.txMaxData-min(c.txMaxData, c.txSentData))
				n := int(min(unsent, limit))
				fin := st.closed && !st.finSent && uint64(n) == unsent
				if n == 0 && !fin {
					break
				}
				n = min(n, room-len(b)-streamFrameOverhead(st.id, st.snext, 1400))
				if n < 0 {
					break
				}
				if uint64(n) < unsent {
					fin = false
				}
				data := st.sbuf[st.snext-st.sbase : st.snext-st.sbase+uint64(n)]
				b = appendStream(b, st.id, st.snext, data, fin)
				p.stream = append(p.stream, ackRange{st.snext, st.snext + uint64(n)})
				st.snext += uint64(n)
				c.txSentData += uint64(n)
				if fin {
					st.finSent, p.fin = true, true
				}
				elicit()
				if n == 0 {
					break
				}
			}
			st.mu.Unlock()
		}
		if c.pingPending && !p.ackEliciting {
			b = appendVarint(b, frPing)
			elicit()
		}
		c.pingPending = false
	}
	if c.ptoCount > 0 && !p.ackEliciting && len(s.sent) == 0 && sp == c.probeSpace() {
		b = appendVarint(b, frPing)
		elicit()
	}
	return b, p
}

func (c *Conn) probeSpace() int {
	for sp := spApp; sp >= spInitial; sp-- {
		if c.spaces[sp].tx != nil && !c.spaces[sp].discarded {
			return sp
		}
	}
	return spInitial
}

func (c *Conn) fail(err error) {
	c.closing = true
	c.closeErr = err
}

func (c *Conn) terminate(err error) {
	c.closeOnce.Do(func() {
		if c.closeErr == nil {
			c.closeErr = err
		}
		close(c.done)
		if c.stream != nil {
			c.stream.signal()
		}
		if c.tls != nil {
			c.tls.Close()
		}
	})
}

func (c *Conn) run(onExit func()) {
	defer onExit()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.mu.Lock()
		if c.closing && c.sentClose {
			c.mu.Unlock()
			c.terminate(ErrClosed)
			return
		}
		if t := c.nextTimer(); !t.IsZero() {
			timer.Reset(max(time.Until(t), time.Millisecond))
		} else {
			timer.Reset(time.Hour)
		}
		c.mu.Unlock()
		select {
		case <-c.done:
			return
		case d := <-c.in:
			c.mu.Lock()
			c.handleDatagram(d)
			for more := true; more; {
				select {
				case d := <-c.in:
					c.handleDatagram(d)
				default:
					more = false
				}
			}
			c.flush()
			c.mu.Unlock()
		case <-c.wake:
			c.mu.Lock()
			c.flush()
			c.mu.Unlock()
		case <-timer.C:
			c.mu.Lock()
			c.onTimer()
			c.flush()
			c.mu.Unlock()
		}
	}
}

func (c *Conn) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if !c.closing {
		c.closing = true
	}
	c.mu.Unlock()
	c.poke()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		c.terminate(ErrClosed)
	}
	return nil
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

type Stream struct {
	c         *Conn
	id        uint64
	mu        sync.Mutex
	rbuf      []byte
	rnext     uint64
	rparts    map[uint64][]byte
	rfin      bool
	rfinAt    uint64
	consumed  uint64
	rxMax     uint64
	maxUpdate bool
	resetErr  error
	sbuf      []byte
	sbase     uint64
	snext     uint64
	sacked    rangeSet
	lost      []ackRange
	closed    bool
	finSent   bool
	finAcked  bool
	writeErr  error
	peerMax   uint64
	notify    chan struct{}
	rdl, wdl  time.Time
}

func newStream(c *Conn, id uint64) *Stream {
	return &Stream{c: c, id: id, rparts: map[uint64][]byte{}, rxMax: recvWindow, notify: make(chan struct{}, 1)}
}

func (st *Stream) signal() {
	select {
	case st.notify <- struct{}{}:
	default:
	}
}

func (st *Stream) receive(off uint64, data []byte, fin bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	end := off + uint64(len(data))
	if end > st.rxMax {
		return errFlowControl
	}
	if fin {
		st.rfin, st.rfinAt = true, end
	}
	if end > st.rnext {
		if newBytes := end - max(off, st.rnext); end > st.rnext {
			st.c.rxReceived += newBytes
			if st.c.rxReceived > st.c.rxMaxData {
				return errFlowControl
			}
		}
		st.rparts[off] = append([]byte(nil), data...)
	}
	for {
		progressed := false
		for o, d := range st.rparts {
			e := o + uint64(len(d))
			if e <= st.rnext {
				delete(st.rparts, o)
				continue
			}
			if o <= st.rnext {
				st.rbuf = append(st.rbuf, d[st.rnext-o:]...)
				st.rnext = e
				delete(st.rparts, o)
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	st.signal()
	return nil
}

func (st *Stream) acked(r ackRange) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if r.hi <= r.lo {
		return
	}
	st.sacked.add(r.lo, r.hi-1)
	for len(st.sacked) > 0 && st.sacked[0].lo <= st.sbase {
		if st.sacked[0].hi+1 > st.sbase {
			n := st.sacked[0].hi + 1 - st.sbase
			n = min(n, uint64(len(st.sbuf)))
			st.sbuf = st.sbuf[n:]
			st.sbase += n
		}
		st.sacked = st.sacked[1:]
	}
	if len(st.sbuf) == 0 {
		st.sbuf = nil
	}
	st.signal()
}

func (st *Stream) Read(p []byte) (int, error) {
	for {
		st.mu.Lock()
		if len(st.rbuf) > 0 {
			n := copy(p, st.rbuf)
			st.rbuf = st.rbuf[n:]
			st.consumed += uint64(n)
			st.c.mu.Lock()
			st.c.rxConsumed += uint64(n)
			if st.c.rxMaxData-st.c.rxConsumed < connRecvWindow/2 {
				st.c.maxDataUpdate = true
			}
			st.c.mu.Unlock()
			if st.rxMax-st.consumed < recvWindow/2 {
				st.maxUpdate = true
			}
			st.mu.Unlock()
			st.c.poke()
			return n, nil
		}
		if st.rfin && st.rnext >= st.rfinAt {
			st.mu.Unlock()
			return 0, io.EOF
		}
		if st.resetErr != nil {
			err := st.resetErr
			st.mu.Unlock()
			return 0, err
		}
		dl := st.rdl
		st.mu.Unlock()
		select {
		case <-st.c.done:
			return 0, io.EOF
		default:
		}
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case <-st.notify:
		case <-st.c.done:
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		if st.writeErr != nil || st.closed {
			err := st.writeErr
			st.mu.Unlock()
			if err == nil {
				err = io.ErrClosedPipe
			}
			return total, err
		}
		space := maxSendBuffer - len(st.sbuf)
		if space > 0 {
			n := min(space, len(p))
			st.sbuf = append(st.sbuf, p[:n]...)
			p = p[n:]
			total += n
			st.mu.Unlock()
			st.c.poke()
			continue
		}
		dl := st.wdl
		st.mu.Unlock()
		var timeout <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return total, os.ErrDeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timeout = t.C
		}
		select {
		case <-st.notify:
		case <-st.c.done:
			return total, ErrClosed
		case <-timeout:
			return total, os.ErrDeadlineExceeded
		}
	}
	return total, nil
}

func (st *Stream) Close() error {
	st.mu.Lock()
	st.closed = true
	st.mu.Unlock()
	st.c.poke()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st.mu.Lock()
		done := st.finAcked || len(st.sbuf) == 0
		st.mu.Unlock()
		if done {
			break
		}
		select {
		case <-st.notify:
		case <-st.c.done:
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
	return st.c.Close()
}

func (st *Stream) LocalAddr() net.Addr  { return st.c.pc.LocalAddr() }
func (st *Stream) RemoteAddr() net.Addr { return st.c.addr }

func (st *Stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.rdl = t
	st.mu.Unlock()
	st.signal()
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.wdl = t
	st.mu.Unlock()
	return nil
}

func (st *Stream) ConnectionState() tls.ConnectionState { return st.c.ConnectionState() }
