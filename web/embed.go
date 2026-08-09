package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist fallback
var files embed.FS

func Assets() fs.FS {
	root := "dist"
	if _, err := fs.Stat(files, "dist/index.html"); err != nil {
		root = "fallback"
	}
	assets, err := fs.Sub(files, root)
	if err != nil {
		panic(err)
	}
	return assets
}
