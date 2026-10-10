package safe

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

type closer struct{ closed int }

func (c *closer) Close() error {
	c.closed++
	return nil
}

func TestRecoverLogsAndClosesAfterPanic(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	c := &closer{}
	func() {
		defer Recover(log, "test connection", c)
		panic("boom")
	}()
	if c.closed != 1 {
		t.Fatalf("closed %d times, want 1", c.closed)
	}
	out := buf.String()
	for _, want := range []string{"level=ERROR", "test connection panic", "err=boom", "stack="} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q is missing %q", out, want)
		}
	}
}

func TestRecoverWithoutPanicLeavesConnectionOpen(t *testing.T) {
	var buf bytes.Buffer
	c := &closer{}
	func() {
		defer Recover(slog.New(slog.NewTextHandler(&buf, nil)), "test connection", c)
	}()
	if c.closed != 0 || buf.Len() != 0 {
		t.Fatalf("closed %d times and logged %q without a panic", c.closed, buf.String())
	}
}

func TestRecoverWithoutLoggerOrConnection(t *testing.T) {
	var nilLog *slog.Logger
	func() {
		defer Recover(nilLog, "test", nil)
		panic("boom")
	}()
}
