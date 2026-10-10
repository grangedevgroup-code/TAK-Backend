package safe

import (
	"io"
	"log/slog"
	"runtime/debug"
)

func Recover(log *slog.Logger, what string, c io.Closer) {
	r := recover()
	if r == nil {
		return
	}
	if log != nil {
		log.Error(what+" panic", "err", r, "stack", string(debug.Stack()))
	}
	if c != nil {
		_ = c.Close()
	}
}
