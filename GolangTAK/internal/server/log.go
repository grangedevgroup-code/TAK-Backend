package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type LogBuffer struct {
	mu      sync.Mutex
	lines   []string
	next    int
	full    bool
	file    *os.File
	path    string
	size    int64
	limit   int64
	console io.Writer
	subs    map[chan string]struct{}
}

func NewLogBuffer(path string, console io.Writer) *LogBuffer {
	b := &LogBuffer{lines: make([]string, 2000), path: path, limit: 10 << 20, console: console, subs: map[chan string]struct{}{}}
	if path != "" {
		os.MkdirAll(filepath.Dir(path), 0o755)
		b.open()
	}
	return b
}

func (b *LogBuffer) open() {
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		b.file = nil
		return
	}
	b.file = f
	if st, err := f.Stat(); err == nil {
		b.size = st.Size()
	}
}

func (b *LogBuffer) rotate() {
	b.file.Close()
	for i := 3; i >= 2; i-- {
		os.Rename(fmt.Sprintf("%s.%d", b.path, i-1), fmt.Sprintf("%s.%d", b.path, i))
	}
	failed := false
	if err := os.Rename(b.path, b.path+".1"); err != nil {
		failed = os.Truncate(b.path, 0) != nil
	}
	b.size = 0
	b.open()
	if failed {
		b.size = 0
	}
}

func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file != nil {
		if b.size+int64(len(p)) > b.limit {
			b.rotate()
		}
		if b.file != nil {
			n, _ := b.file.Write(p)
			b.size += int64(n)
		}
	}
	if b.console != nil {
		b.console.Write(p)
	}
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		b.lines[b.next] = line
		b.next = (b.next + 1) % len(b.lines)
		if b.next == 0 {
			b.full = true
		}
		for ch := range b.subs {
			select {
			case ch <- line:
			default:
			}
		}
	}
	return len(p), nil
}

func (b *LogBuffer) Tail(n int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var all []string
	if b.full {
		all = append(all, b.lines[b.next:]...)
	}
	all = append(all, b.lines[:b.next]...)
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return append([]string(nil), all...)
}

func (b *LogBuffer) Subscribe() (chan string, func()) {
	ch := make(chan string, 256)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

func (b *LogBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file != nil {
		err := b.file.Close()
		b.file = nil
		return err
	}
	return nil
}

type lineHandler struct {
	w     io.Writer
	level *slog.LevelVar
	attrs []slog.Attr
	mu    *sync.Mutex
}

func NewLogger(w io.Writer, level *slog.LevelVar) *slog.Logger {
	return slog.New(&lineHandler{w: w, level: level, mu: &sync.Mutex{}})
}

func (h *lineHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

func quoteValue(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\n\"=") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Time.UTC().Format("2006-01-02 15:04:05"))
	sb.WriteByte(' ')
	switch {
	case r.Level >= slog.LevelError:
		sb.WriteString("ERROR")
	case r.Level >= slog.LevelWarn:
		sb.WriteString("WARN ")
	case r.Level >= slog.LevelInfo:
		sb.WriteString("INFO ")
	default:
		sb.WriteString("DEBUG")
	}
	sb.WriteByte(' ')
	sb.WriteString(strings.ReplaceAll(r.Message, "\n", " "))
	write := func(a slog.Attr) bool {
		sb.WriteByte(' ')
		sb.WriteString(a.Key)
		sb.WriteByte('=')
		sb.WriteString(quoteValue(a.Value.String()))
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	sb.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, sb.String())
	return err
}

func (h *lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &n
}

func (h *lineHandler) WithGroup(string) slog.Handler { return h }

func ParseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
