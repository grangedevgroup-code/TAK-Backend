package media

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	liveTimescale = 90000
	hlsTarget     = 2 * liveTimescale
	hlsKeep       = 7
	gopLimit      = 600
	liveIdle      = time.Minute
)

var ErrNoVideo = errors.New("the stream has no H.264 video")

type hlsSegment struct {
	n    int
	data []byte
	dur  float64
}

type LiveViewer struct {
	C       chan []byte
	Done    chan struct{}
	once    sync.Once
	waitKey bool
}

func (v *LiveViewer) close() { v.once.Do(func() { close(v.Done) }) }

type Live struct {
	st    *Stream
	track int
	sub   *Subscriber
	dep   *H264Depacketizer

	mu       sync.Mutex
	ready    chan struct{}
	readyOK  bool
	init     []byte
	codec    string
	viewers  map[*LiveViewer]struct{}
	seq      uint32
	base     uint64
	pending  *AccessUnit
	started  bool
	gop      [][]byte
	segs     []hlsSegment
	cur      []byte
	curDur   uint64
	nextSeg  int
	lastUsed time.Time
	stopped  bool
}

func h264Track(d *Description) int {
	for i, t := range d.Tracks {
		if t.Media == "video" && t.Codec == "H264" {
			return i
		}
	}
	return -1
}

func LiveFor(st *Stream) (*Live, error) {
	track := h264Track(st.Desc)
	if track < 0 {
		return nil, ErrNoVideo
	}
	for {
		v, loaded := st.LoadOrStoreMeta("live", &Live{st: st, track: track, ready: make(chan struct{}), viewers: map[*LiveViewer]struct{}{}, lastUsed: time.Now()})
		l := v.(*Live)
		if loaded {
			l.mu.Lock()
			stopped := l.stopped
			l.lastUsed = time.Now()
			l.mu.Unlock()
			if stopped {
				st.meta.CompareAndDelete("live", l)
				continue
			}
			return l, nil
		}
		if err := l.start(); err != nil {
			st.meta.CompareAndDelete("live", l)
			return nil, err
		}
		return l, nil
	}
}

func (l *Live) start() error {
	sub, err := l.st.Subscribe(4096)
	if err != nil {
		return err
	}
	l.sub = sub
	t := l.st.Desc.Tracks[l.track]
	l.dep = &H264Depacketizer{OnAU: l.onAU}
	l.dep.SPS, l.dep.PPS = t.H264Params()
	go l.run()
	return nil
}

func (l *Live) run() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	defer l.stop()
	for {
		select {
		case <-l.sub.Done:
			return
		case <-tick.C:
			l.mu.Lock()
			idle := len(l.viewers) == 0 && time.Since(l.lastUsed) > liveIdle
			l.mu.Unlock()
			if idle {
				return
			}
		case p := <-l.sub.C:
			if p.RTCP || p.Track != l.track {
				continue
			}
			h, payload, err := ParseRTP(p.Data)
			if err != nil {
				continue
			}
			l.dep.Push(h, payload)
		}
	}
}

func (l *Live) stop() {
	l.st.Unsubscribe(l.sub)
	l.mu.Lock()
	l.stopped = true
	for v := range l.viewers {
		v.close()
	}
	l.viewers = map[*LiveViewer]struct{}{}
	if !l.readyOK {
		l.readyOK = true
		close(l.ready)
	}
	l.mu.Unlock()
	l.st.meta.CompareAndDelete("live", l)
}

func (l *Live) onAU(au AccessUnit) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.init == nil {
		if !au.Key || l.dep.SPS == nil || l.dep.PPS == nil {
			return
		}
		info, err := ParseSPS(l.dep.SPS)
		if err != nil {
			return
		}
		l.init = InitSegment(l.dep.SPS, l.dep.PPS, info, liveTimescale)
		l.codec = info.Codec()
		l.readyOK = true
		close(l.ready)
	}
	if !l.started {
		if !au.Key {
			return
		}
		l.started = true
	}
	if l.pending != nil {
		dur := au.Timestamp - l.pending.Timestamp
		if dur == 0 || dur > 5*liveTimescale {
			dur = 3000
		}
		l.emit(*l.pending, dur)
	}
	if au.Key && l.dep.SPS != nil && l.dep.PPS != nil && !hasType(au.NALUs, nalSPS) {
		au.NALUs = append([][]byte{l.dep.SPS, l.dep.PPS}, au.NALUs...)
	}
	l.pending = &au
}

func hasType(nalus [][]byte, t byte) bool {
	for _, n := range nalus {
		if n[0]&0x1f == t {
			return true
		}
	}
	return false
}

func (l *Live) emit(au AccessUnit, dur uint32) {
	frag := Fragment(l.seq, l.base, []Sample{{Data: AVCCSample(au.NALUs), Duration: dur, Key: au.Key}})
	l.seq++
	l.base += uint64(dur)
	if au.Key {
		l.gop = l.gop[:0]
		if l.curDur >= hlsTarget && len(l.cur) > 0 {
			l.segs = append(l.segs, hlsSegment{n: l.nextSeg, data: l.cur, dur: float64(l.curDur) / liveTimescale})
			l.nextSeg++
			if len(l.segs) > hlsKeep {
				l.segs = l.segs[len(l.segs)-hlsKeep:]
			}
			l.cur, l.curDur = nil, 0
		}
	}
	if len(l.cur) > 0 || au.Key {
		l.cur = append(l.cur, frag...)
		l.curDur += uint64(dur)
	}
	if len(l.gop) < gopLimit {
		l.gop = append(l.gop, frag)
	}
	for v := range l.viewers {
		if v.waitKey {
			if !au.Key {
				continue
			}
			v.waitKey = false
		}
		select {
		case v.C <- frag:
		default:
			v.close()
			delete(l.viewers, v)
		}
	}
}

func (l *Live) Wait(timeout time.Duration) error {
	select {
	case <-l.ready:
	case <-time.After(timeout):
		return errors.New("no video arrived from the stream yet")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.init == nil {
		return errors.New("the stream ended")
	}
	return nil
}

func (l *Live) Codec() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.codec
}

func (l *Live) Init() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.init
}

func (l *Live) Watch() *LiveViewer {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := &LiveViewer{C: make(chan []byte, gopLimit+256), Done: make(chan struct{})}
	if l.stopped {
		v.close()
		return v
	}
	if len(l.gop) > 0 {
		for _, f := range l.gop {
			v.C <- f
		}
	} else {
		v.waitKey = true
	}
	l.viewers[v] = struct{}{}
	l.lastUsed = time.Now()
	return v
}

func (l *Live) Unwatch(v *LiveViewer) {
	l.mu.Lock()
	delete(l.viewers, v)
	l.lastUsed = time.Now()
	l.mu.Unlock()
	v.close()
}

func (l *Live) touch() {
	l.mu.Lock()
	l.lastUsed = time.Now()
	l.mu.Unlock()
}

func (l *Live) Playlist() (string, bool) {
	l.touch()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.segs) == 0 {
		return "", false
	}
	target := 1.0
	for _, s := range l.segs {
		target = math.Max(target, math.Ceil(s.dur))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:%d\n#EXT-X-INDEPENDENT-SEGMENTS\n#EXT-X-MAP:URI=\"init.mp4\"\n", int(target), l.segs[0].n)
	for _, s := range l.segs {
		fmt.Fprintf(&b, "#EXTINF:%.3f,\nseg%d.m4s\n", s.dur, s.n)
	}
	return b.String(), true
}

func (l *Live) Segment(n int) ([]byte, bool) {
	l.touch()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.segs {
		if s.n == n {
			return s.data, true
		}
	}
	return nil, false
}
