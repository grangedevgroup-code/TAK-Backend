package media

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	rtmpChunkOut   = 4096
	rtmpWindow     = 2500000
	rtmpMaxMessage = 16 << 20
)

type RTMPServer struct {
	Registry *Registry
	Auth     AuthFunc
	Log      interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
	}

	mu     sync.Mutex
	lns    []net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

func NewRTMPServer(reg *Registry) *RTMPServer {
	return &RTMPServer{Registry: reg, conns: map[net.Conn]struct{}{}}
}

func (s *RTMPServer) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return net.ErrClosed
	}
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		s.mu.Lock()
		s.conns[nc] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				nc.Close()
				s.mu.Lock()
				delete(s.conns, nc)
				s.mu.Unlock()
			}()
			c := &rtmpConn{s: s, nc: nc, br: bufio.NewReaderSize(nc, 64<<10), inChunk: 128, chunks: map[uint32]*rtmpChunkState{}}
			if err := c.run(); err != nil && s.Log != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.Log.Warn("rtmp connection ended", "remote", nc.RemoteAddr().String(), "err", err)
			}
		}()
	}
}

func (s *RTMPServer) Close() {
	s.mu.Lock()
	s.closed = true
	for _, l := range s.lns {
		l.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

type rtmpChunkState struct {
	ts       uint32
	delta    uint32
	length   uint32
	typ      byte
	streamID uint32
	extended bool
	buf      []byte
}

type rtmpConn struct {
	s        *RTMPServer
	nc       net.Conn
	br       *bufio.Reader
	inChunk  uint32
	chunks   map[uint32]*rtmpChunkState
	received uint64
	acked    uint64
	app      string
	query    url.Values
	user     string

	stream  *Stream
	path    string
	video   *flvVideo
	audio   *flvAudio
	pending []rtmpMedia
	started time.Time
}

type rtmpMedia struct {
	typ  byte
	ts   uint32
	data []byte
}

func (c *rtmpConn) run() error {
	c.nc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := c.handshake(); err != nil {
		return err
	}
	defer func() {
		if c.stream != nil {
			if c.s.Log != nil {
				c.s.Log.Info("video stream stopped", "path", c.stream.Name)
			}
			c.s.Registry.Unpublish(c.stream)
		}
	}()
	for {
		c.nc.SetReadDeadline(time.Now().Add(60 * time.Second))
		typ, ts, sid, msg, err := c.readMessage()
		if err != nil {
			return err
		}
		if err := c.handle(typ, ts, sid, msg); err != nil {
			return err
		}
	}
}

func (c *rtmpConn) handshake() error {
	c1 := make([]byte, 1537)
	if _, err := io.ReadFull(c.br, c1); err != nil {
		return err
	}
	if c1[0] != 3 {
		return fmt.Errorf("unsupported rtmp version %d", c1[0])
	}
	s1 := make([]byte, 1536)
	binary.BigEndian.PutUint32(s1, uint32(time.Now().Unix()))
	rand.Read(s1[8:])
	out := append([]byte{3}, s1...)
	out = append(out, c1[1:]...)
	if _, err := c.nc.Write(out); err != nil {
		return err
	}
	c2 := make([]byte, 1536)
	_, err := io.ReadFull(c.br, c2)
	return err
}

func (c *rtmpConn) read(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(c.br, b)
	c.received += uint64(n)
	return b, err
}

func be24(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }

func (c *rtmpConn) readMessage() (byte, uint32, uint32, []byte, error) {
	for {
		h, err := c.read(1)
		if err != nil {
			return 0, 0, 0, nil, err
		}
		format := h[0] >> 6
		csid := uint32(h[0] & 0x3f)
		switch csid {
		case 0:
			b, err := c.read(1)
			if err != nil {
				return 0, 0, 0, nil, err
			}
			csid = 64 + uint32(b[0])
		case 1:
			b, err := c.read(2)
			if err != nil {
				return 0, 0, 0, nil, err
			}
			csid = 64 + uint32(b[0]) + uint32(b[1])*256
		}
		st := c.chunks[csid]
		if st == nil {
			if format != 0 {
				return 0, 0, 0, nil, errors.New("rtmp chunk stream started without a full header")
			}
			if len(c.chunks) > 64 {
				return 0, 0, 0, nil, errors.New("too many rtmp chunk streams")
			}
			st = &rtmpChunkState{}
			c.chunks[csid] = st
		}
		var tsField uint32
		switch format {
		case 0:
			b, err := c.read(11)
			if err != nil {
				return 0, 0, 0, nil, err
			}
			tsField = be24(b)
			st.length, st.typ, st.streamID = be24(b[3:]), b[6], binary.LittleEndian.Uint32(b[7:])
		case 1:
			b, err := c.read(7)
			if err != nil {
				return 0, 0, 0, nil, err
			}
			tsField = be24(b)
			st.length, st.typ = be24(b[3:]), b[6]
		case 2:
			b, err := c.read(3)
			if err != nil {
				return 0, 0, 0, nil, err
			}
			tsField = be24(b)
		}
		if format < 3 {
			st.extended = tsField == 0xffffff
		}
		if st.extended {
			b, err := c.read(4)
			if err != nil {
				return 0, 0, 0, nil, err
			}
			if format < 3 {
				tsField = binary.BigEndian.Uint32(b)
			}
		}
		if len(st.buf) == 0 {
			switch format {
			case 0:
				st.ts = tsField
			case 1, 2:
				st.delta = tsField
				st.ts += tsField
			case 3:
				st.ts += st.delta
			}
		}
		if st.length > rtmpMaxMessage {
			return 0, 0, 0, nil, errors.New("rtmp message too large")
		}
		n := min(st.length-uint32(len(st.buf)), c.inChunk)
		b, err := c.read(int(n))
		if err != nil {
			return 0, 0, 0, nil, err
		}
		st.buf = append(st.buf, b...)
		if c.received-c.acked >= rtmpWindow {
			c.acked = c.received
			c.send(2, 3, 0, 0, binary.BigEndian.AppendUint32(nil, uint32(c.received)))
		}
		if uint32(len(st.buf)) >= st.length {
			msg := st.buf
			st.buf = nil
			return st.typ, st.ts, st.streamID, msg, nil
		}
	}
}

func (c *rtmpConn) send(csid uint32, typ byte, ts, sid uint32, payload []byte) error {
	var out []byte
	first := true
	for len(payload) > 0 || first {
		if first {
			h := []byte{byte(csid)}
			h = append(h, byte(ts>>16), byte(ts>>8), byte(ts))
			h = append(h, byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)), typ)
			h = binary.LittleEndian.AppendUint32(h, sid)
			out = append(out, h...)
		} else {
			out = append(out, 0xc0|byte(csid))
		}
		n := min(len(payload), rtmpChunkOut)
		out = append(out, payload[:n]...)
		payload = payload[n:]
		first = false
	}
	c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.nc.Write(out)
	return err
}

func (c *rtmpConn) command(sid uint32, vals ...any) error {
	return c.send(3, 20, 0, sid, amfEncode(vals...))
}

func (c *rtmpConn) handle(typ byte, ts, sid uint32, msg []byte) error {
	switch typ {
	case 1:
		if len(msg) >= 4 {
			size := binary.BigEndian.Uint32(msg) & 0x7fffffff
			if size < 1 || size > rtmpMaxMessage {
				return errors.New("bad rtmp chunk size")
			}
			c.inChunk = size
		}
	case 20, 17:
		if typ == 17 && len(msg) > 0 {
			msg = msg[1:]
		}
		vals, err := amfDecode(msg)
		if err != nil && len(vals) < 2 {
			return err
		}
		return c.handleCommand(sid, vals)
	case 8, 9:
		return c.media(typ, ts, msg)
	}
	return nil
}

func amfStr(vals []any, i int) string {
	if i < len(vals) {
		if s, ok := vals[i].(string); ok {
			return s
		}
	}
	return ""
}

func (c *rtmpConn) handleCommand(sid uint32, vals []any) error {
	name := amfStr(vals, 0)
	var tx float64
	if len(vals) > 1 {
		tx, _ = vals[1].(float64)
	}
	switch name {
	case "connect":
		if len(vals) > 2 {
			if obj, ok := vals[2].(amfObject); ok {
				c.app, _ = obj["app"].(string)
				if tc, ok := obj["tcUrl"].(string); ok {
					if u, err := url.Parse(tc); err == nil {
						c.query = u.Query()
					}
				}
			}
		}
		app, q, _ := strings.Cut(c.app, "?")
		c.app = strings.Trim(app, "/")
		if q != "" {
			if v, err := url.ParseQuery(q); err == nil {
				c.query = v
			}
		}
		c.send(2, 5, 0, 0, binary.BigEndian.AppendUint32(nil, rtmpWindow))
		c.send(2, 6, 0, 0, append(binary.BigEndian.AppendUint32(nil, rtmpWindow), 2))
		c.send(2, 1, 0, 0, binary.BigEndian.AppendUint32(nil, rtmpChunkOut))
		return c.command(0, "_result", tx, amfObject{"fmsVer": "FMS/3,0,1,123", "capabilities": 31.0}, amfObject{"level": "status", "code": "NetConnection.Connect.Success", "description": "Connection succeeded.", "objectEncoding": 0.0})
	case "releaseStream", "FCPublish", "_checkbw":
		return c.command(0, "_result", tx, nil, amfUndefined{})
	case "createStream":
		return c.command(0, "_result", tx, nil, 1.0)
	case "publish":
		key := amfStr(vals, 3)
		name, q, _ := strings.Cut(key, "?")
		query := c.query
		if q != "" {
			if v, err := url.ParseQuery(q); err == nil {
				query = v
			}
		}
		path, err := CleanPath(strings.Trim(c.app+"/"+name, "/"))
		if err != nil {
			c.status(sid, "error", "NetStream.Publish.BadName", err.Error())
			return err
		}
		if c.s.Auth != nil {
			user, err := c.s.Auth(query.Get("user"), firstNonEmpty(query.Get("pass"), query.Get("password")), true, path, c.nc.RemoteAddr().String())
			if err != nil {
				c.status(sid, "error", "NetStream.Publish.Unauthorized", "sign in with ?user=NAME&pass=PASSWORD on the stream URL")
				return err
			}
			c.user = user
		}
		if _, busy := c.s.Registry.Get(path); busy {
			c.status(sid, "error", "NetStream.Publish.BadName", "another stream is using this path")
			return ErrPathInUse
		}
		c.path = path
		c.started = time.Now()
		c.send(2, 4, 0, 0, []byte{0, 0, 0, 0, 0, byte(sid)})
		return c.status(sid, "status", "NetStream.Publish.Start", "Publishing "+path)
	case "FCUnpublish", "deleteStream", "closeStream":
		return io.EOF
	case "play":
		c.status(sid, "error", "NetStream.Play.Failed", "play streams over RTSP or HLS")
		return errors.New("rtmp playback is not supported")
	}
	return nil
}

func (c *rtmpConn) status(sid uint32, level, code, desc string) error {
	return c.command(sid, "onStatus", 0.0, nil, amfObject{"level": level, "code": code, "description": desc})
}

func (c *rtmpConn) media(typ byte, ts uint32, msg []byte) error {
	if c.path == "" || len(msg) == 0 {
		return nil
	}
	if typ == 9 {
		if c.video == nil {
			if msg[0]&0x0f != 7 {
				return errors.New("only H.264 video is supported over RTMP")
			}
			if len(msg) >= 5 && msg[1] == 0 {
				v, err := parseAVCConfig(msg[5:])
				if err != nil {
					return err
				}
				c.video = v
			}
		} else if len(msg) >= 5 && msg[1] == 0 {
			if v, err := parseAVCConfig(msg[5:]); err == nil {
				c.video.sps, c.video.pps = v.sps, v.pps
			}
			return nil
		}
	} else if c.audio == nil && msg[0]>>4 == 10 && len(msg) >= 2 && msg[1] == 0 {
		a, err := parseAACConfig(msg[2:])
		if err == nil {
			c.audio = a
		}
		return nil
	}
	if c.stream == nil {
		if c.video == nil {
			if len(c.pending) < 200 {
				c.pending = append(c.pending, rtmpMedia{typ: typ, ts: ts, data: msg})
				return nil
			}
			return errors.New("the RTMP stream sent no H.264 configuration")
		}
		if c.audio == nil && time.Since(c.started) < 2*time.Second && len(c.pending) < 200 {
			c.pending = append(c.pending, rtmpMedia{typ: typ, ts: ts, data: msg})
			return nil
		}
		if err := c.startStream(); err != nil {
			return err
		}
		pend := c.pending
		c.pending = nil
		for _, p := range pend {
			c.forward(p.typ, p.ts, p.data)
		}
	}
	c.forward(typ, ts, msg)
	return nil
}

func (c *rtmpConn) startStream() error {
	var sdp strings.Builder
	sdp.WriteString("v=0\r\ns=RTMP\r\nt=0 0\r\n")
	fmt.Fprintf(&sdp, "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;profile-level-id=%s;sprop-parameter-sets=%s,%s\r\na=control:trackID=0\r\n",
		hex.EncodeToString(c.video.sps[1:4]), base64.StdEncoding.EncodeToString(c.video.sps), base64.StdEncoding.EncodeToString(c.video.pps))
	if c.audio != nil {
		fmt.Fprintf(&sdp, "m=audio 0 RTP/AVP 97\r\na=rtpmap:97 MPEG4-GENERIC/%d/%d\r\na=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=%s\r\na=control:trackID=1\r\n",
			c.audio.rate, c.audio.channels, hex.EncodeToString(c.audio.config))
	}
	desc, err := ParseSDP([]byte(sdp.String()))
	if err != nil {
		return err
	}
	st, err := c.s.Registry.Publish(c.path, desc, firstNonEmpty(c.user, "anonymous"), "rtmp "+c.nc.RemoteAddr().String())
	if err != nil {
		return err
	}
	c.stream = st
	c.video.ssrc = randUint32()
	if c.audio != nil {
		c.audio.ssrc = randUint32()
	}
	if c.s.Log != nil {
		c.s.Log.Info("video stream started", "path", st.Name, "user", st.Publisher, "remote", c.nc.RemoteAddr().String(), "protocol", "rtmp")
	}
	return nil
}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (c *rtmpConn) forward(typ byte, ts uint32, msg []byte) {
	if typ == 9 && c.video != nil && len(msg) >= 5 && msg[1] == 1 {
		cts := int32(be24(msg[2:])<<8) >> 8
		au := AccessUnit{Timestamp: uint32(int64(ts)*90 + int64(cts)*90), Key: msg[0]>>4 == 1}
		data := msg[5:]
		for len(data) >= 4 {
			n := int(binary.BigEndian.Uint32(data))
			data = data[4:]
			if n <= 0 || n > len(data) {
				break
			}
			au.NALUs = append(au.NALUs, data[:n])
			data = data[n:]
		}
		if au.Key && !hasType(au.NALUs, nalSPS) {
			au.NALUs = append([][]byte{c.video.sps, c.video.pps}, au.NALUs...)
		}
		for _, pkt := range PacketizeH264(au, 96, c.video.ssrc, &c.video.seq, 1400) {
			c.stream.Write(Packet{Track: 0, Data: pkt})
		}
		return
	}
	if typ == 8 && c.audio != nil && len(msg) > 2 && msg[0]>>4 == 10 && msg[1] == 1 {
		frame := msg[2:]
		if len(frame) > 8191 {
			return
		}
		payload := []byte{0, 16, byte(len(frame) >> 5), byte(len(frame)<<3) & 0xf8}
		payload = append(payload, frame...)
		pkt := MarshalRTP(RTPHeader{Marker: true, PayloadType: 97, Seq: c.audio.seq, Timestamp: uint32(uint64(ts) * uint64(c.audio.rate) / 1000), SSRC: c.audio.ssrc}, payload)
		c.audio.seq++
		c.stream.Write(Packet{Track: 1, Data: pkt})
	}
}

type flvVideo struct {
	sps, pps []byte
	ssrc     uint32
	seq      uint16
}

type flvAudio struct {
	config   []byte
	rate     int
	channels int
	ssrc     uint32
	seq      uint16
}

func parseAVCConfig(b []byte) (*flvVideo, error) {
	if len(b) < 8 || b[0] != 1 {
		return nil, errors.New("bad AVC configuration")
	}
	pos := 5
	nsps := int(b[pos] & 0x1f)
	pos++
	v := &flvVideo{}
	for i := 0; i < nsps; i++ {
		if pos+2 > len(b) {
			return nil, errors.New("bad AVC configuration")
		}
		n := int(binary.BigEndian.Uint16(b[pos:]))
		pos += 2
		if pos+n > len(b) {
			return nil, errors.New("bad AVC configuration")
		}
		if v.sps == nil {
			v.sps = append([]byte(nil), b[pos:pos+n]...)
		}
		pos += n
	}
	if pos >= len(b) {
		return nil, errors.New("bad AVC configuration")
	}
	npps := int(b[pos])
	pos++
	for i := 0; i < npps; i++ {
		if pos+2 > len(b) {
			return nil, errors.New("bad AVC configuration")
		}
		n := int(binary.BigEndian.Uint16(b[pos:]))
		pos += 2
		if pos+n > len(b) {
			return nil, errors.New("bad AVC configuration")
		}
		if v.pps == nil {
			v.pps = append([]byte(nil), b[pos:pos+n]...)
		}
		pos += n
	}
	if len(v.sps) < 4 || len(v.pps) == 0 {
		return nil, errors.New("AVC configuration has no SPS or PPS")
	}
	return v, nil
}

var aacRates = []int{96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350}

func parseAACConfig(b []byte) (*flvAudio, error) {
	if len(b) < 2 {
		return nil, errors.New("bad AAC configuration")
	}
	idx := int(b[0]&0x07)<<1 | int(b[1]>>7)
	if idx >= len(aacRates) {
		return nil, errors.New("unsupported AAC sample rate")
	}
	ch := int(b[1]>>3) & 0x0f
	if ch == 0 {
		ch = 2
	}
	return &flvAudio{config: append([]byte(nil), b...), rate: aacRates[idx], channels: ch}, nil
}
