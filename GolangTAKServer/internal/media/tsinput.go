package media

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func IsTSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (strings.EqualFold(u.Scheme, "udp") || strings.EqualFold(u.Scheme, "rtp"))
}

func listenTS(raw string) (*net.UDPConn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		return nil, errors.New("the UDP address needs a port, for example udp://0.0.0.0:5600")
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	if addr.IP != nil && addr.IP.IsMulticast() {
		var ifi *net.Interface
		if name := u.Query().Get("iface"); name != "" {
			if ifi, err = net.InterfaceByName(name); err != nil {
				return nil, err
			}
		}
		return net.ListenMulticastUDP("udp", ifi, addr)
	}
	return net.ListenUDP("udp", addr)
}

type tsPublisher struct {
	reg       *Registry
	path      string
	publisher string
	source    string
	stream    *Stream
	sps, pps  []byte
	ssrc      uint32
	seq       uint16
	klvSSRC   uint32
	klvSeq    uint16
	hasKLV    bool
	lastPTS   int64
	err       error
}

func (p *tsPublisher) video(pts int64, annexB []byte) {
	nals := SplitAnnexB(annexB)
	if len(nals) == 0 {
		return
	}
	key := false
	var keep [][]byte
	for _, n := range nals {
		if len(n) == 0 {
			continue
		}
		switch n[0] & 0x1f {
		case nalSPS:
			p.sps = append([]byte(nil), n...)
		case nalPPS:
			p.pps = append([]byte(nil), n...)
		case nalIDR:
			key = true
		case 9:
			continue
		}
		keep = append(keep, n)
	}
	if pts >= 0 {
		p.lastPTS = pts
	}
	if p.stream == nil {
		if !key || p.sps == nil || p.pps == nil || p.err != nil {
			return
		}
		if err := p.start(); err != nil {
			p.err = err
			return
		}
	}
	au := AccessUnit{Timestamp: uint32(p.lastPTS), NALUs: keep, Key: key}
	if key && !hasType(au.NALUs, nalSPS) {
		au.NALUs = append([][]byte{p.sps, p.pps}, au.NALUs...)
	}
	for _, pkt := range PacketizeH264(au, 96, p.ssrc, &p.seq, 1400) {
		p.stream.Write(Packet{Track: 0, Data: pkt})
	}
}

func (p *tsPublisher) klv(pts int64, data []byte) {
	p.hasKLV = true
	if p.stream == nil {
		if p.reg.OnMetadata != nil {
			p.reg.OnMetadata(&Stream{Name: p.path, Source: p.source, Publisher: p.publisher}, data)
		}
		return
	}
	ts := p.lastPTS
	if pts >= 0 {
		ts = pts
	}
	for len(data) > 0 {
		chunk := min(len(data), 1400)
		last := chunk == len(data)
		pkt := MarshalRTP(RTPHeader{Marker: last, PayloadType: 98, Seq: p.klvSeq, Timestamp: uint32(ts), SSRC: p.klvSSRC}, data[:chunk])
		p.klvSeq++
		p.stream.Write(Packet{Track: 1, Data: pkt})
		data = data[chunk:]
	}
}

func (p *tsPublisher) start() error {
	var sdp strings.Builder
	sdp.WriteString("v=0\r\ns=MPEG-TS\r\nt=0 0\r\n")
	fmt.Fprintf(&sdp, "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;profile-level-id=%s;sprop-parameter-sets=%s,%s\r\na=control:trackID=0\r\n",
		hex.EncodeToString(p.sps[1:min(4, len(p.sps))]), base64.StdEncoding.EncodeToString(p.sps), base64.StdEncoding.EncodeToString(p.pps))
	sdp.WriteString("m=application 0 RTP/AVP 98\r\na=rtpmap:98 smpte336m/90000\r\na=control:trackID=1\r\n")
	desc, err := ParseSDP([]byte(sdp.String()))
	if err != nil {
		return err
	}
	st, err := p.reg.Publish(p.path, desc, p.publisher, p.source)
	if err != nil {
		return err
	}
	p.stream = st
	p.ssrc, p.klvSSRC = randUint32(), randUint32()
	return nil
}

func PullTS(ctx context.Context, raw string, reg *Registry, path, publisher string) error {
	conn, err := listenTS(raw)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	pub := &tsPublisher{reg: reg, path: path, publisher: publisher, source: "udp " + conn.LocalAddr().String(), lastPTS: 0}
	defer func() {
		if pub.stream != nil {
			reg.Unpublish(pub.stream)
		}
	}()
	d := NewTSDemuxer()
	d.OnVideo = pub.video
	d.OnKLV = pub.klv
	buf := make([]byte, 65536)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return errors.New("no MPEG-TS data received for 30 seconds")
			}
			return err
		}
		b := buf[:n]
		if len(b) > 12 && b[0] != 0x47 && b[0]>>6 == 2 {
			if _, payload, err := ParseRTP(b); err == nil {
				b = payload
			}
		}
		d.Write(b)
		if pub.err != nil {
			return pub.err
		}
	}
}
