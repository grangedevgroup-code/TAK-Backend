package flock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x", "test.lock")
	a, err := Acquire(p)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	if Owner(p) != os.Getpid() {
		t.Fatalf("owner %d", Owner(p))
	}
	if _, err := Acquire(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire: %v", err)
	}
	a.Release()
	b, err := Acquire(p)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	b.Release()
	b.Release()
}
