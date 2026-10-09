package media

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Packet struct {
	Track int
	RTCP  bool
	Data  []byte
}

type Subscriber struct {
	C       chan Packet
	Done    chan struct{}
	Dropped atomic.Int64
	once    sync.Once
}

func (s *Subscriber) close() { s.once.Do(func() { close(s.Done) }) }

type Stream struct {
	Name      string
	Desc      *Description
	Publisher string
	Source    string
	Started   time.Time

	PacketsIn atomic.Int64
	BytesIn   atomic.Int64

	mu      sync.RWMutex
	subs    map[*Subscriber]struct{}
	closed  bool
	done    chan struct{}
	meta    sync.Map
	lastPkt atomic.Int64
	klv     *klvTrack
}

func (s *Stream) Done() <-chan struct{} { return s.done }

func (s *Stream) Write(p Packet) {
	s.PacketsIn.Add(1)
	s.BytesIn.Add(int64(len(p.Data)))
	s.lastPkt.Store(time.Now().UnixNano())
	if s.klv != nil && p.Track == s.klv.track && !p.RTCP {
		s.klv.push(s, p.Data)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for sub := range s.subs {
		select {
		case sub.C <- p:
		default:
			sub.Dropped.Add(1)
		}
	}
}

func (s *Stream) LastPacket() time.Time {
	n := s.lastPkt.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

func (s *Stream) Subscribe(buf int) (*Subscriber, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrNoStream
	}
	sub := &Subscriber{C: make(chan Packet, buf), Done: make(chan struct{})}
	s.subs[sub] = struct{}{}
	return sub, nil
}

func (s *Stream) Unsubscribe(sub *Subscriber) {
	s.mu.Lock()
	delete(s.subs, sub)
	s.mu.Unlock()
	sub.close()
}

func (s *Stream) Readers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}

func (s *Stream) Meta(key string) (any, bool) { return s.meta.Load(key) }

func (s *Stream) SetMeta(key string, v any) { s.meta.Store(key, v) }

func (s *Stream) LoadOrStoreMeta(key string, v any) (any, bool) { return s.meta.LoadOrStore(key, v) }

func (s *Stream) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	subs := s.subs
	s.subs = map[*Subscriber]struct{}{}
	close(s.done)
	s.mu.Unlock()
	for sub := range subs {
		sub.close()
	}
}

var (
	ErrNoStream   = errors.New("no stream is being published at that path")
	ErrPathInUse  = errors.New("another stream is already being published at that path")
	ErrBadPath    = errors.New("stream paths use letters, numbers, dashes, dots, underscores and slashes")
	ErrTooMany    = errors.New("the server has reached its stream limit")
	ErrNotAllowed = errors.New("not allowed")
)

type Registry struct {
	MaxStreams  int
	OnPublish   func(*Stream)
	OnUnpublish func(*Stream)
	OnMetadata  func(*Stream, []byte)

	mu      sync.Mutex
	streams map[string]*Stream
}

func NewRegistry() *Registry { return &Registry{streams: map[string]*Stream{}} }

func CleanPath(p string) (string, error) {
	p = strings.Trim(p, "/")
	if p == "" || len(p) > 200 {
		return "", ErrBadPath
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", ErrBadPath
		}
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '/' || r == '~') {
			return "", ErrBadPath
		}
	}
	return p, nil
}

func (r *Registry) Publish(name string, desc *Description, publisher, source string) (*Stream, error) {
	name, err := CleanPath(name)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if _, ok := r.streams[name]; ok {
		r.mu.Unlock()
		return nil, ErrPathInUse
	}
	if r.MaxStreams > 0 && len(r.streams) >= r.MaxStreams {
		r.mu.Unlock()
		return nil, ErrTooMany
	}
	s := &Stream{Name: name, Desc: desc, Publisher: publisher, Source: source, Started: time.Now(), subs: map[*Subscriber]struct{}{}, done: make(chan struct{})}
	if r.OnMetadata != nil && desc != nil {
		for i, t := range desc.Tracks {
			if strings.EqualFold(t.Codec, "smpte336m") {
				s.klv = &klvTrack{track: i, emit: r.OnMetadata}
				break
			}
		}
	}
	r.streams[name] = s
	r.mu.Unlock()
	if r.OnPublish != nil {
		r.OnPublish(s)
	}
	return s, nil
}

func (r *Registry) Unpublish(s *Stream) {
	r.mu.Lock()
	if cur, ok := r.streams[s.Name]; ok && cur == s {
		delete(r.streams, s.Name)
	}
	r.mu.Unlock()
	s.close()
	if r.OnUnpublish != nil {
		r.OnUnpublish(s)
	}
}

func (r *Registry) Get(name string) (*Stream, bool) {
	name, err := CleanPath(name)
	if err != nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.streams[name]
	return s, ok
}

func (r *Registry) List() []*Stream {
	r.mu.Lock()
	out := make([]*Stream, 0, len(r.streams))
	for _, s := range r.streams {
		out = append(out, s)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Registry) CloseAll() {
	for _, s := range r.List() {
		r.Unpublish(s)
	}
}

type klvTrack struct {
	track int
	emit  func(*Stream, []byte)
	mu    sync.Mutex
	buf   []byte
}

func (k *klvTrack) push(s *Stream, pkt []byte) {
	h, payload, err := ParseRTP(pkt)
	if err != nil {
		return
	}
	k.mu.Lock()
	k.buf = append(k.buf, payload...)
	var out []byte
	if h.Marker || len(k.buf) > 1<<16 {
		out, k.buf = k.buf, nil
	}
	k.mu.Unlock()
	if len(out) > 0 {
		k.emit(s, out)
	}
}
