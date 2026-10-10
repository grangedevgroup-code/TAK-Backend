package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var ErrNotFound = errors.New("store: not found")

type record struct {
	K string          `json:"k"`
	V json.RawMessage `json:"v,omitempty"`
	D bool            `json:"d,omitempty"`
}

type Collection[T any] struct {
	mu      sync.RWMutex
	path    string
	raw     map[string][]byte
	f       *os.File
	w       *bufio.Writer
	writes  int
	durable bool
	Skipped int
	hookMu  sync.RWMutex
	hook    func(key string, raw []byte, deleted bool)
}

func (c *Collection[T]) SetOnChange(fn func(key string, raw []byte, deleted bool)) {
	c.hookMu.Lock()
	c.hook = fn
	c.hookMu.Unlock()
}

func (c *Collection[T]) changed(key string, raw []byte, deleted bool) {
	c.hookMu.RLock()
	fn := c.hook
	c.hookMu.RUnlock()
	if fn != nil {
		fn(key, raw, deleted)
	}
}

func (c *Collection[T]) ApplyRaw(key string, raw []byte, deleted bool) error {
	if key == "" {
		return errors.New("store: empty key")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if deleted {
		if _, ok := c.raw[key]; !ok {
			return nil
		}
		delete(c.raw, key)
		return c.appendLocked(record{K: key, D: true})
	}
	if !json.Valid(raw) {
		return errors.New("store: invalid value")
	}
	if old, ok := c.raw[key]; ok && bytes.Equal(old, raw) {
		return nil
	}
	b := append([]byte(nil), raw...)
	c.raw[key] = b
	return c.appendLocked(record{K: key, V: b})
}

func (c *Collection[T]) Snapshot() map[string][]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string][]byte, len(c.raw))
	for k, v := range c.raw {
		out[k] = v
	}
	return out
}

func Open[T any](path string, durable bool) (*Collection[T], error) {
	c := &Collection[T]{path: path, raw: map[string][]byte{}, durable: durable}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := c.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	c.f = f
	c.w = bufio.NewWriterSize(f, 64<<10)
	if c.writes > 1000 && c.writes > 2*len(c.raw) {
		if err := c.compactLocked(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Collection[T]) load() error {
	f, err := os.Open(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 256<<10)
	var good int64
	var offset int64
	for {
		line, err := r.ReadBytes('\n')
		offset += int64(len(line))
		complete := err == nil
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			var rec record
			if jerr := json.Unmarshal(trimmed, &rec); jerr != nil || rec.K == "" {
				if !complete {
					break
				}
				c.Skipped++
			} else {
				c.writes++
				if rec.D {
					delete(c.raw, rec.K)
				} else {
					c.raw[rec.K] = append([]byte(nil), rec.V...)
				}
			}
		}
		if complete {
			good = offset
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if st, err := f.Stat(); err == nil && st.Size() > good {
		f.Close()
		if err := os.Truncate(c.path, good); err != nil {
			return fmt.Errorf("store: repairing %s: %w", c.path, err)
		}
	}
	return nil
}

func (c *Collection[T]) appendLocked(rec record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	if c.durable {
		if err := c.f.Sync(); err != nil {
			return err
		}
	}
	c.writes++
	if c.writes > 1000 && c.writes > 2*len(c.raw)+100 {
		return c.compactLocked()
	}
	return nil
}

func (c *Collection[T]) compactLocked() error {
	tmp := c.path + ".compact"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 256<<10)
	keys := make([]string, 0, len(c.raw))
	for k := range c.raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, err := json.Marshal(record{K: k, V: c.raw[k]})
		if err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if c.f != nil {
		c.w.Flush()
		c.f.Close()
		c.f = nil
	}
	if err := os.Rename(tmp, c.path); err != nil {
		os.Remove(c.path)
		if err2 := os.Rename(tmp, c.path); err2 != nil {
			return err2
		}
	}
	nf, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	c.f = nf
	c.w = bufio.NewWriterSize(nf, 64<<10)
	c.writes = len(c.raw)
	return nil
}

func (c *Collection[T]) decode(b []byte) (T, error) {
	var v T
	err := json.Unmarshal(b, &v)
	return v, err
}

func (c *Collection[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	b, ok := c.raw[key]
	c.mu.RUnlock()
	if !ok {
		var zero T
		return zero, false
	}
	v, err := c.decode(b)
	if err != nil {
		var zero T
		return zero, false
	}
	return v, true
}

func (c *Collection[T]) Has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.raw[key]
	return ok
}

func (c *Collection[T]) Put(key string, v T) error {
	if key == "" {
		return errors.New("store: empty key")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if old, ok := c.raw[key]; ok && bytes.Equal(old, b) {
		c.mu.Unlock()
		return nil
	}
	c.raw[key] = b
	err = c.appendLocked(record{K: key, V: b})
	c.mu.Unlock()
	c.changed(key, b, false)
	return err
}

func (c *Collection[T]) Delete(key string) error {
	c.mu.Lock()
	if _, ok := c.raw[key]; !ok {
		c.mu.Unlock()
		return nil
	}
	delete(c.raw, key)
	err := c.appendLocked(record{K: key, D: true})
	c.mu.Unlock()
	c.changed(key, nil, true)
	return err
}

func (c *Collection[T]) Update(key string, fn func(v T, exists bool) (T, bool, error)) (T, error) {
	var notify func()
	defer func() {
		if notify != nil {
			notify()
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	var cur T
	b, exists := c.raw[key]
	if exists {
		var err error
		cur, err = c.decode(b)
		if err != nil {
			return cur, err
		}
	}
	next, keep, err := fn(cur, exists)
	if err != nil {
		return cur, err
	}
	if !keep {
		if exists {
			delete(c.raw, key)
			notify = func() { c.changed(key, nil, true) }
			return next, c.appendLocked(record{K: key, D: true})
		}
		return next, nil
	}
	nb, err := json.Marshal(next)
	if err != nil {
		return cur, err
	}
	if exists && bytes.Equal(nb, b) {
		return next, nil
	}
	c.raw[key] = nb
	notify = func() { c.changed(key, nb, false) }
	return next, c.appendLocked(record{K: key, V: nb})
}

func (c *Collection[T]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.raw)
}

func (c *Collection[T]) Keys() []string {
	c.mu.RLock()
	keys := make([]string, 0, len(c.raw))
	for k := range c.raw {
		keys = append(keys, k)
	}
	c.mu.RUnlock()
	sort.Strings(keys)
	return keys
}

func (c *Collection[T]) All() []T {
	c.mu.RLock()
	keys := make([]string, 0, len(c.raw))
	for k := range c.raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals := make([][]byte, len(keys))
	for i, k := range keys {
		vals[i] = c.raw[k]
	}
	c.mu.RUnlock()
	out := make([]T, 0, len(vals))
	for _, b := range vals {
		if v, err := c.decode(b); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func (c *Collection[T]) Each(fn func(key string, v T) bool) {
	keys := c.Keys()
	for _, k := range keys {
		v, ok := c.Get(k)
		if !ok {
			continue
		}
		if !fn(k, v) {
			return
		}
	}
}

func (c *Collection[T]) Sync() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return nil
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	return c.f.Sync()
}

func (c *Collection[T]) Compact() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.compactLocked()
}

func (c *Collection[T]) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return nil
	}
	err := errors.Join(c.w.Flush(), c.f.Sync(), c.f.Close())
	c.f = nil
	return err
}

type Blobs struct {
	dir string
}

func OpenBlobs(dir string) (*Blobs, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Blobs{dir: dir}, nil
}

func ValidHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (b *Blobs) Path(hash string) string {
	hash = strings.ToLower(hash)
	if !ValidHash(hash) {
		return ""
	}
	return filepath.Join(b.dir, hash[:2], hash)
}

func (b *Blobs) Put(r io.Reader, limit int64) (string, int64, error) {
	tmp, err := os.CreateTemp(b.dir, ".upload-*")
	if err != nil {
		return "", 0, err
	}
	name := tmp.Name()
	h := sha256.New()
	src := r
	if limit > 0 {
		src = io.LimitReader(r, limit+1)
	}
	n, err := io.Copy(io.MultiWriter(tmp, h), src)
	if err == nil && limit > 0 && n > limit {
		err = fmt.Errorf("store: file larger than %d bytes", limit)
	}
	if err == nil {
		err = tmp.Sync()
	}
	cerr := tmp.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", 0, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	dst := b.Path(sum)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		os.Remove(name)
		return "", 0, err
	}
	if _, err := os.Stat(dst); err == nil {
		os.Remove(name)
		return sum, n, nil
	}
	if err := os.Rename(name, dst); err != nil {
		os.Remove(name)
		return "", 0, err
	}
	return sum, n, nil
}

func (b *Blobs) PutBytes(data []byte) (string, error) {
	h, _, err := b.Put(bytes.NewReader(data), 0)
	return h, err
}

func (b *Blobs) Open(hash string) (*os.File, error) {
	p := b.Path(hash)
	if p == "" {
		return nil, ErrNotFound
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return f, err
}

func (b *Blobs) Read(hash string) ([]byte, error) {
	p := b.Path(hash)
	if p == "" {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return data, err
}

func (b *Blobs) Exists(hash string) bool {
	p := b.Path(hash)
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func (b *Blobs) Size(hash string) int64 {
	p := b.Path(hash)
	if p == "" {
		return -1
	}
	st, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return st.Size()
}

func (b *Blobs) Delete(hash string) error {
	p := b.Path(hash)
	if p == "" {
		return nil
	}
	err := os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (b *Blobs) Usage() (int64, int) {
	var total int64
	count := 0
	filepath.WalkDir(b.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && ValidHash(d.Name()) {
			total += info.Size()
			count++
		}
		return nil
	})
	return total, count
}
