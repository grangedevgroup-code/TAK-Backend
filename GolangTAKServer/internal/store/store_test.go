package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type user struct {
	Name   string
	Groups []string
	N      int
}

func TestCollectionPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.jsonl")
	c, err := Open[user](path, true)
	if err != nil {
		t.Fatal(err)
	}
	c.Put("alice", user{Name: "alice", Groups: []string{"a"}})
	c.Put("bob", user{Name: "bob"})
	c.Delete("bob")
	got, _ := c.Get("alice")
	got.Groups[0] = "mutated"
	again, _ := c.Get("alice")
	if again.Groups[0] != "a" {
		t.Fatal("Get returned shared state")
	}
	if _, err := c.Update("alice", func(u user, ok bool) (user, bool, error) {
		u.N++
		return u, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"k":"carol","v":{"Name":"car`)
	f.Close()
	c2, err := Open[user](path, false)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Len() != 1 || c2.Has("bob") || c2.Has("carol") {
		t.Fatalf("reload: %v", c2.Keys())
	}
	if a, _ := c2.Get("alice"); a.N != 1 {
		t.Fatal("update lost")
	}
	c2.Put("dave", user{Name: "dave"})
	c2.Close()
	c3, _ := Open[user](path, false)
	if !c3.Has("dave") || c3.Len() != 2 {
		t.Fatalf("after repair: %v", c3.Keys())
	}
	c3.Close()
}

func TestCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.jsonl")
	c, _ := Open[user](path, false)
	for i := 0; i < 3000; i++ {
		c.Put(fmt.Sprintf("k%d", i%10), user{N: i})
	}
	st, _ := os.Stat(path)
	if st.Size() > 100000 {
		t.Fatalf("journal not compacted: %d bytes", st.Size())
	}
	c.Close()
	c2, _ := Open[user](path, false)
	if c2.Len() != 10 {
		t.Fatal("lost keys")
	}
	v, _ := c2.Get("k9")
	if v.N != 2999 {
		t.Fatalf("latest value lost: %d", v.N)
	}
	all := c2.All()
	if len(all) != 10 {
		t.Fatal("All")
	}
	c2.Close()
}

func TestConcurrentUpdates(t *testing.T) {
	c, _ := Open[user](filepath.Join(t.TempDir(), "x.jsonl"), false)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.Update("counter", func(u user, ok bool) (user, bool, error) {
					u.N++
					return u, true, nil
				})
			}
		}()
	}
	wg.Wait()
	if v, _ := c.Get("counter"); v.N != 1000 {
		t.Fatalf("lost updates: %d", v.N)
	}
	c.Close()
}

func TestBlobs(t *testing.T) {
	b, err := OpenBlobs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h, n, err := b.Put(strings.NewReader("hello"), 0)
	if err != nil || n != 5 || h != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("put: %s %d %v", h, n, err)
	}
	h2, _ := b.PutBytes([]byte("hello"))
	if h2 != h || !b.Exists(h) || b.Size(h) != 5 {
		t.Fatal("dedupe")
	}
	data, _ := b.Read(h)
	if !bytes.Equal(data, []byte("hello")) {
		t.Fatal("read")
	}
	if _, _, err := b.Put(strings.NewReader("toolarge"), 3); err == nil {
		t.Fatal("limit not enforced")
	}
	if b.Path("../../etc/passwd") != "" || b.Exists("zz") {
		t.Fatal("path traversal")
	}
	if total, count := b.Usage(); total != 5 || count != 1 {
		t.Fatalf("usage %d %d", total, count)
	}
	b.Delete(h)
	if b.Exists(h) {
		t.Fatal("delete")
	}
}
