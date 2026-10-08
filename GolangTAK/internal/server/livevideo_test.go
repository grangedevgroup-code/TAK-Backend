package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/media"
)

var (
	videoSPS, _ = hex.DecodeString("6764001eacd940a02ff97011000003000100000300320f162d96")
	videoPPS, _ = hex.DecodeString("68ebe3cb22c0")
)

func videoSDP() []byte {
	return []byte("v=0\r\ns=Cam\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=" +
		base64.StdEncoding.EncodeToString(videoSPS) + "," + base64.StdEncoding.EncodeToString(videoPPS) + "\r\na=control:trackID=0\r\n")
}

func publishTestVideo(t *testing.T, raw string) *media.Client {
	t.Helper()
	c, err := media.Dial(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	desc, _ := media.ParseSDP(videoSDP())
	if err := c.Announce(desc); err != nil {
		c.Close()
		t.Fatal(err)
	}
	go func() {
		var seq uint16
		for i := 0; ; i++ {
			key := i%25 == 0
			slice := bytes.Repeat([]byte{byte(i)}, 400)
			slice[0] = 0x41
			au := media.AccessUnit{Timestamp: uint32(i * 3600), NALUs: [][]byte{slice}}
			if key {
				slice[0] = 0x65
				au.NALUs = [][]byte{videoSPS, videoPPS, slice}
				au.Key = true
			}
			for _, pkt := range media.PacketizeH264(au, 96, 9, &seq, 1200) {
				if c.WritePacket(media.Packet{Data: pkt}) != nil {
					return
				}
			}
			time.Sleep(4 * time.Millisecond)
		}
	}()
	return c
}

func TestLiveVideoServer(t *testing.T) {
	rtspPort := freePort(t)
	s := newTestServer(t, func(c *Config) {
		c.Video = VideoServerConfig{Enabled: true, RTSPPort: rtspPort, AnonymousRead: true, RecordPaths: []string{"live"}, RecordMinutes: 30}
	})
	s.dir.AddUser("pilot", "pilot-password", false, nil)
	base := "rtsp://127.0.0.1:" + strconv.Itoa(rtspPort) + "/live/uas1"

	anon, err := media.Dial(context.Background(), base, nil)
	if err != nil {
		t.Fatal(err)
	}
	desc, _ := media.ParseSDP(videoSDP())
	if err := anon.Announce(desc); err == nil {
		t.Fatal("anonymous publishing was allowed")
	}
	anon.Close()
	if bad, err := media.Dial(context.Background(), "rtsp://pilot:wrong@127.0.0.1:"+strconv.Itoa(rtspPort)+"/live/uas1", nil); err == nil {
		if err := bad.Announce(desc); err == nil {
			t.Fatal("wrong password was accepted")
		}
		bad.Close()
	}

	pub := publishTestVideo(t, "rtsp://pilot:pilot-password@127.0.0.1:"+strconv.Itoa(rtspPort)+"/live/uas1")
	defer pub.Close()
	waitFor(t, "the stream to be listed as a video feed", 5*time.Second, func() bool {
		_, ok := s.videos.Get(streamFeedUID("live/uas1"))
		return ok
	})
	f, _ := s.videos.Get(streamFeedUID("live/uas1"))
	if f.URL() != "rtsp://127.0.0.1:"+strconv.Itoa(rtspPort)+"/live/uas1" || f.Creator != "pilot" {
		t.Fatalf("video feed: %+v %s", f, f.URL())
	}

	s.dir.AddUser("viewer", "viewer-password", true, nil)
	secret, _, err := s.dir.CreateToken("viewer", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	auth := map[string]string{"Authorization": "Bearer " + secret}
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/video/streams"), nil, auth)
	var list struct {
		Streams []streamView `json:"streams"`
	}
	if st != 200 || json.Unmarshal(body, &list) != nil || len(list.Streams) != 1 || !list.Streams[0].Browser || list.Streams[0].Publisher != "pilot" {
		t.Fatalf("streams: %d %s", st, body)
	}

	req, _ := http.NewRequest("GET", plainURL(s, "/api/video/live/live/uas1/live.mp4"), nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "avc1.64001E") {
		t.Fatalf("live.mp4: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	buf := make([]byte, 64<<10)
	n, _ := io.ReadAtLeast(resp.Body, buf, 2048)
	resp.Body.Close()
	if !bytes.Contains(buf[:n], []byte("ftyp")) || !bytes.Contains(buf[:n], []byte("moof")) {
		t.Fatal("live.mp4 did not start with an init segment and a fragment")
	}

	waitFor(t, "an HLS playlist", 15*time.Second, func() bool {
		st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/video/live/live/uas1/index.m3u8"), nil, auth)
		return st == 200 && strings.Contains(string(body), "#EXT-X-MAP")
	})

	waitFor(t, "recording to start", 10*time.Second, func() bool { return s.isRecording("live/uas1") })
	time.Sleep(1500 * time.Millisecond)
	pub.Close()
	var recs []recordingMeta
	waitFor(t, "the recording to be saved", 10*time.Second, func() bool {
		_, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/video/recordings"), nil, auth)
		json.Unmarshal(body, &recs)
		return len(recs) == 1
	})
	if recs[0].Path != "live/uas1" || recs[0].Duration <= 0 || recs[0].Width != 640 {
		t.Fatalf("recording: %+v", recs[0])
	}
	fileURL := plainURL(s, "/api/video/recordings/live/uas1/"+recs[0].File)
	st, body = doReq(t, http.DefaultClient, "GET", fileURL, nil, map[string]string{"Authorization": "Bearer " + secret, "Range": "bytes=0-99"})
	if st != http.StatusPartialContent || len(body) != 100 || string(body[4:8]) != "ftyp" {
		t.Fatalf("ranged recording: %d %d", st, len(body))
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/video/recordings/live/uas1/..%2f..%2fconfig.json"), nil, auth); st != http.StatusNotFound {
		t.Fatalf("path traversal: %d", st)
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", fileURL, nil, auth); st != http.StatusNoContent {
		t.Fatal("delete recording failed")
	}
	waitFor(t, "the video feed to be removed after the stream ended", 5*time.Second, func() bool {
		_, ok := s.videos.Get(streamFeedUID("live/uas1"))
		return !ok
	})
}
