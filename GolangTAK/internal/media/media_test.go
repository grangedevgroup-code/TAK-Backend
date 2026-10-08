package media

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	testSPS, _ = hex.DecodeString("6764001eacd940a02ff97011000003000100000300320f162d96")
	testPPS, _ = hex.DecodeString("68ebe3cb22c0")
)

func TestParseSPS(t *testing.T) {
	info, err := ParseSPS(testSPS)
	if err != nil {
		t.Fatal(err)
	}
	if info.Width != 640 || info.Height != 360 || info.Codec() != "avc1.64001E" {
		t.Fatalf("got %+v %s", info, info.Codec())
	}
}

func testSDP() []byte {
	return []byte("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Test\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=" +
		base64.StdEncoding.EncodeToString(testSPS) + "," + base64.StdEncoding.EncodeToString(testPPS) + "\r\na=control:streamid=0\r\n")
}

func fakeAU(i int) AccessUnit {
	key := i%25 == 0
	size := 300
	typ := byte(1)
	if key {
		size, typ = 5000, nalIDR|0x60
	}
	slice := bytes.Repeat([]byte{byte(i)}, size)
	slice[0] = typ
	au := AccessUnit{Timestamp: uint32(i * 3600), Key: key, NALUs: [][]byte{slice}}
	if key {
		au.NALUs = append([][]byte{testSPS, testPPS}, au.NALUs...)
	}
	return au
}

func TestH264RoundTrip(t *testing.T) {
	var got []AccessUnit
	d := &H264Depacketizer{OnAU: func(au AccessUnit) { got = append(got, au) }}
	var seq uint16
	for i := 0; i < 3; i++ {
		for _, pkt := range PacketizeH264(fakeAU(i), 96, 1, &seq, 1200) {
			h, payload, err := ParseRTP(pkt)
			if err != nil {
				t.Fatal(err)
			}
			d.Push(h, payload)
		}
	}
	if len(got) != 3 || !got[0].Key || got[1].Key || len(got[0].NALUs) != 3 || !bytes.Equal(got[0].NALUs[2], fakeAU(0).NALUs[2]) {
		t.Fatalf("depacketized %d units", len(got))
	}
	if !bytes.Equal(d.SPS, testSPS) {
		t.Fatal("sps not captured")
	}
}

func startServer(t *testing.T, auth AuthFunc, udpPort int) (*Server, *Registry, string) {
	t.Helper()
	reg := NewRegistry()
	srv := NewServer(reg, nil)
	srv.Auth = auth
	if udpPort > 0 {
		if err := srv.ListenUDP("127.0.0.1", udpPort); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(srv.Close)
	return srv, reg, ln.Addr().String()
}

func publish(t *testing.T, raw string, frames int, delay time.Duration) *Client {
	t.Helper()
	c, err := Dial(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := ParseSDP(testSDP())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Announce(desc); err != nil {
		t.Fatal(err)
	}
	go func() {
		var seq uint16
		for i := 0; frames <= 0 || i < frames; i++ {
			for _, pkt := range PacketizeH264(fakeAU(i), 96, 7, &seq, 1200) {
				if c.WritePacket(Packet{Data: pkt}) != nil {
					return
				}
			}
			time.Sleep(delay)
		}
	}()
	return c
}

func TestRTSPPublishAndPlay(t *testing.T) {
	_, reg, addr := startServer(t, nil, 0)
	pub := publish(t, "rtsp://"+addr+"/live/cam1", 0, 10*time.Millisecond)
	defer pub.Close()
	waitStream(t, reg, "live/cam1")

	c, err := Dial(context.Background(), "rtsp://"+addr+"/live/cam1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	desc, err := c.Describe()
	if err != nil {
		t.Fatal(err)
	}
	if len(desc.Tracks) != 1 || desc.Tracks[0].Codec != "H264" || desc.Tracks[0].Control != "trackID=0" {
		t.Fatalf("describe: %+v", desc.Tracks[0])
	}
	if err := c.SetupPlay(desc); err != nil {
		t.Fatal(err)
	}
	n := 0
	errDone := errors.New("done")
	err = c.ReadPackets(5*time.Second, func(p Packet) {
		if _, _, err := ParseRTP(p.Data); err == nil {
			n++
		}
		if n >= 50 {
			c.Close()
		}
	})
	if n < 50 {
		t.Fatalf("received %d packets (%v)", n, err)
	}
	_ = errDone
	st, _ := reg.Get("live/cam1")
	if st.PacketsIn.Load() == 0 {
		t.Fatal("no packets counted")
	}

	pub2, err := Dial(context.Background(), "rtsp://"+addr+"/live/cam1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pub2.Close()
	d2, _ := ParseSDP(testSDP())
	if err := pub2.Announce(d2); err == nil {
		t.Fatal("a second publisher took a busy path")
	}

	pub.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := reg.Get("live/cam1"); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("stream not removed after the publisher left")
}

func waitStream(t *testing.T, reg *Registry, name string) *Stream {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, ok := reg.Get(name); ok {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stream %s never appeared", name)
	return nil
}

func TestRTSPAuth(t *testing.T) {
	auth := func(user, pass string, publish bool, path, remote string) (string, error) {
		if user == "" {
			return "", ErrUnauthorized
		}
		if user != "pilot" || pass != "secret" {
			return "", ErrForbidden
		}
		return user, nil
	}
	_, reg, addr := startServer(t, auth, 0)
	c, err := Dial(context.Background(), "rtsp://"+addr+"/uas", nil)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := ParseSDP(testSDP())
	if err := c.Announce(d); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("anonymous publish: %v", err)
	}
	c.Close()
	pub := publish(t, "rtsp://pilot:secret@"+addr+"/uas", 0, 10*time.Millisecond)
	defer pub.Close()
	st := waitStream(t, reg, "uas")
	if st.Publisher != "pilot" {
		t.Fatalf("publisher %q", st.Publisher)
	}
}

func freeUDPPair(t *testing.T) int {
	t.Helper()
	for p := 31000; p < 32000; p += 2 {
		a, err1 := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		b, err2 := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p + 1})
		if a != nil {
			a.Close()
		}
		if b != nil {
			b.Close()
		}
		if err1 == nil && err2 == nil {
			return p
		}
	}
	t.Fatal("no free udp ports")
	return 0
}

func TestRTSPUDPPlayback(t *testing.T) {
	port := freeUDPPair(t)
	_, reg, addr := startServer(t, nil, port)
	pub := publish(t, "rtsp://"+addr+"/udp", 0, 10*time.Millisecond)
	defer pub.Close()
	waitStream(t, reg, "udp")
	rtp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rtp.Close()
	c, err := Dial(context.Background(), "rtsp://"+addr+"/udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	desc, err := c.Describe()
	if err != nil {
		t.Fatal(err)
	}
	lp := rtp.LocalAddr().(*net.UDPAddr).Port
	resp, err := c.Do("SETUP", c.trackURL(desc.Tracks[0]), map[string]string{"Transport": fmt.Sprintf("RTP/AVP;unicast;client_port=%d-%d", lp, lp+1)}, nil)
	if err != nil || !strings.Contains(resp.Get("transport"), fmt.Sprintf("server_port=%d-%d", port, port+1)) {
		t.Fatalf("setup: %v %v", err, resp)
	}
	if _, err := c.Do("PLAY", c.base, nil, nil); err != nil {
		t.Fatal(err)
	}
	rtp.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2000)
	n, _, err := rtp.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseRTP(buf[:n]); err != nil {
		t.Fatal(err)
	}
}

func TestLiveFragmentsAndHLS(t *testing.T) {
	_, reg, addr := startServer(t, nil, 0)
	pub := publish(t, "rtsp://"+addr+"/live/hls", 0, 2*time.Millisecond)
	defer pub.Close()
	st := waitStream(t, reg, "live/hls")
	l, err := LiveFor(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if l.Codec() != "avc1.64001E" || !bytes.HasPrefix(l.Init()[4:], []byte("ftyp")) {
		t.Fatalf("codec %s", l.Codec())
	}
	v := l.Watch()
	defer l.Unwatch(v)
	select {
	case f := <-v.C:
		if string(f[4:8]) != "moof" {
			t.Fatalf("fragment starts with %q", f[4:8])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no fragment")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pl, ok := l.Playlist(); ok {
			if !strings.Contains(pl, "#EXT-X-MAP:URI=\"init.mp4\"") || !strings.Contains(pl, "seg0.m4s") {
				t.Fatalf("playlist: %s", pl)
			}
			seg, ok := l.Segment(0)
			if !ok || string(seg[4:8]) != "moof" {
				t.Fatal("segment 0 missing")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no hls segments")
}

func TestDigestPull(t *testing.T) {
	_, reg, addr := startServer(t, nil, 0)
	pub := publish(t, "rtsp://"+addr+"/source", 0, 10*time.Millisecond)
	defer pub.Close()
	waitStream(t, reg, "source")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go digestProxy(ln, addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Pull(ctx, "rtsp://admin:camera@"+ln.Addr().String()+"/source", nil, reg, "relay/cam", "pull")
	}()
	st := waitStream(t, reg, "relay/cam")
	deadline := time.Now().Add(5 * time.Second)
	for st.PacketsIn.Load() < 20 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if st.PacketsIn.Load() < 20 {
		t.Fatal("pulled stream has no data")
	}
	cancel()
	<-done
}

func digestProxy(ln net.Listener, upstream string) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		go func(nc net.Conn) {
			defer nc.Close()
			up, err := net.Dial("tcp", upstream)
			if err != nil {
				return
			}
			defer up.Close()
			br := newBufReader(nc)
			for {
				req, err := ReadRequest(br)
				if err != nil {
					return
				}
				ah := req.Get("authorization")
				if !strings.HasPrefix(ah, "Digest ") || !strings.Contains(ah, `username="admin"`) {
					writeResponse(nc, req.Get("cseq"), 401, map[string]string{"WWW-Authenticate": `Digest realm="cam", nonce="abc123"`}, nil)
					continue
				}
				p := digestParams(ah[7:])
				want := md5hex(md5hex("admin:cam:camera") + ":abc123:" + md5hex(req.Method+":"+p["uri"]))
				if p["response"] != want {
					writeResponse(nc, req.Get("cseq"), 403, nil, nil)
					return
				}
				var b strings.Builder
				fmt.Fprintf(&b, "%s %s RTSP/1.0\r\n", req.Method, strings.Replace(req.URL, ln.Addr().String(), upstream, 1))
				for k, v := range req.Header {
					if k != "authorization" && k != "content-length" {
						fmt.Fprintf(&b, "%s: %s\r\n", k, v)
					}
				}
				if len(req.Body) > 0 {
					fmt.Fprintf(&b, "content-length: %d\r\n", len(req.Body))
				}
				b.WriteString("\r\n")
				up.Write([]byte(b.String()))
				up.Write(req.Body)
				if req.Method == "PLAY" {
					go func() {
						buf := make([]byte, 65536)
						for {
							n, err := up.Read(buf)
							if err != nil {
								nc.Close()
								return
							}
							nc.Write(buf[:n])
						}
					}()
					continue
				}
				resp, err := ReadResponse(newBufReader(up))
				if err != nil {
					return
				}
				h := map[string]string{}
				for k, v := range resp.Header {
					if k != "cseq" && k != "content-length" && k != "server" && k != "date" {
						h[k] = strings.Replace(v, upstream, ln.Addr().String(), -1)
					}
				}
				writeResponse(nc, req.Get("cseq"), resp.Status, h, resp.Body)
			}
		}(nc)
	}
}

func TestFFmpegInterop(t *testing.T) {
	bin := os.Getenv("FFMPEG_BIN")
	if bin == "" {
		t.Skip("set FFMPEG_BIN to the directory with ffmpeg and ffprobe")
	}
	clip := os.Getenv("FFMPEG_CLIP")
	_, reg, addr := startServer(t, nil, freeUDPPair(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pub := exec.CommandContext(ctx, filepath.Join(bin, "ffmpeg"), "-hide_banner", "-loglevel", "error", "-re", "-stream_loop", "-1", "-i", clip, "-c", "copy", "-f", "rtsp", "-rtsp_transport", "udp", "rtsp://"+addr+"/ff/test")
	var pubErr bytes.Buffer
	pub.Stderr = &pubErr
	if err := pub.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if t.Failed() {
			t.Logf("ffmpeg publisher: %s", pubErr.String())
		}
	}()
	st := waitStream(t, reg, "ff/test")

	for _, transport := range []string{"tcp", "udp"} {
		out, err := exec.Command(filepath.Join(bin, "ffprobe"), "-hide_banner", "-loglevel", "error", "-rtsp_transport", transport, "-show_entries", "stream=codec_name,width,height", "-of", "csv=p=0", "rtsp://"+addr+"/ff/test").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "h264,640,360") {
			t.Fatalf("ffprobe over %s: %v %s", transport, err, out)
		}
	}

	l, err := LiveFor(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Wait(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "index.m3u8"):
			pl, ok := l.Playlist()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(pl))
		case strings.HasSuffix(r.URL.Path, "init.mp4"):
			w.Write(l.Init())
		default:
			var n int
			fmt.Sscanf(filepath.Base(r.URL.Path), "seg%d.m4s", &n)
			seg, ok := l.Segment(n)
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(seg)
		}
	}))
	defer hs.Close()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, ok := l.Playlist(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no hls playlist")
		}
		time.Sleep(200 * time.Millisecond)
	}
	out, err := exec.Command(filepath.Join(bin, "ffprobe"), "-hide_banner", "-loglevel", "error", "-show_entries", "stream=codec_name,width,height", "-of", "csv=p=0", hs.URL+"/index.m3u8").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "h264,640,360") {
		t.Fatalf("ffprobe hls: %v %s", err, out)
	}
	frames, err := exec.Command(filepath.Join(bin, "ffmpeg"), "-hide_banner", "-loglevel", "error", "-i", hs.URL+"/index.m3u8", "-frames:v", "25", "-f", "null", "-").CombinedOutput()
	if err != nil {
		t.Fatalf("decoding hls: %v %s", err, frames)
	}
}

func newBufReader(nc net.Conn) *bufio.Reader { return bufio.NewReader(nc) }

func TestFFmpegRTMP(t *testing.T) {
	bin := os.Getenv("FFMPEG_BIN")
	if bin == "" {
		t.Skip("set FFMPEG_BIN to the directory with ffmpeg and ffprobe")
	}
	reg := NewRegistry()
	srv := NewRTMPServer(reg)
	srv.Auth = func(user, pass string, publish bool, path, remote string) (string, error) {
		if user != "pilot" || pass != "pw" {
			return "", ErrForbidden
		}
		return user, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	_, _, rtspAddr := startServerWith(t, reg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := []string{"-f", "lavfi", "-re", "-i", "testsrc=size=640x360:rate=25", "-f", "lavfi", "-re", "-i", "sine=frequency=440:sample_rate=48000", "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-g", "25", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "64k"}
	bad := exec.CommandContext(ctx, filepath.Join(bin, "ffmpeg"), append(append([]string{"-hide_banner", "-loglevel", "error"}, src...), "-t", "2", "-f", "flv", "rtmp://"+ln.Addr().String()+"/live/drone?user=pilot&pass=wrong")...)
	bad.Run()
	if _, ok := reg.Get("live/drone"); ok {
		t.Fatal("wrong password published")
	}
	var pubErr bytes.Buffer
	pub := exec.CommandContext(ctx, filepath.Join(bin, "ffmpeg"), append(append([]string{"-hide_banner", "-loglevel", "error"}, src...), "-f", "flv", "rtmp://"+ln.Addr().String()+"/live/drone?user=pilot&pass=pw")...)
	pub.Stderr = &pubErr
	if err := pub.Start(); err != nil {
		t.Fatal(err)
	}
	st := waitStream(t, reg, "live/drone")
	if st.Publisher != "pilot" || len(st.Desc.Tracks) != 2 {
		t.Fatalf("stream %+v tracks %d: %s", st.Publisher, len(st.Desc.Tracks), pubErr.String())
	}
	out, err := exec.Command(filepath.Join(bin, "ffprobe"), "-hide_banner", "-loglevel", "error", "-rtsp_transport", "tcp", "-show_entries", "stream=codec_name,width,height,sample_rate", "-of", "csv=p=0", "rtsp://"+rtspAddr+"/live/drone").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "h264,640,360") || !strings.Contains(string(out), "aac,48000") {
		t.Fatalf("ffprobe: %v %s / %s", err, out, pubErr.String())
	}
	frames, err := exec.Command(filepath.Join(bin, "ffmpeg"), "-hide_banner", "-loglevel", "error", "-rtsp_transport", "tcp", "-i", "rtsp://"+rtspAddr+"/live/drone", "-t", "2", "-f", "null", "-").CombinedOutput()
	if err != nil {
		t.Fatalf("decoding the relayed RTMP stream: %v %s", err, frames)
	}
}

func startServerWith(t *testing.T, reg *Registry) (*Server, *Registry, string) {
	t.Helper()
	srv := NewServer(reg, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(srv.Close)
	return srv, reg, ln.Addr().String()
}
