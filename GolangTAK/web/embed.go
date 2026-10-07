package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

func Assets() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

func Index() []byte {
	b, err := files.ReadFile("static/index.html")
	if err != nil {
		return []byte("dashboard missing")
	}
	return b
}
