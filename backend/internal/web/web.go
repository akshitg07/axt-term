// Package web serves the built single-page application from the binary.
//
// Embedding the SPA means one artifact, one container, no CORS, no separate web
// server to configure, and no possibility of the frontend and backend being
// different versions.
package web

import (
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// dist holds the built frontend. `make web-build` writes into this directory.
//
// The placeholder index.html committed here keeps the embed directive valid so
// the backend compiles and runs before the frontend has ever been built -- which
// is what makes the API testable on its own.
//
//go:embed all:dist
var dist embed.FS

// Handler serves static assets with a SPA fallback.
type Handler struct {
	files fs.FS
	index []byte
	// apiPrefixes are paths that must 404 as JSON rather than returning the SPA.
	// Without this, a typo in an API path returns index.html with a 200 and the
	// client reports "unexpected token <" instead of "no such endpoint".
	apiPrefixes []string
	notFound    http.Handler
}

// NewHandler creates the static handler.
func NewHandler(notFound http.Handler) (*Handler, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, errors.New("web: dist/index.html is missing; run `make web-build`")
	}
	return &Handler{
		files:       sub,
		index:       index,
		apiPrefixes: []string{"/api/", "/ws/"},
		notFound:    notFound,
	}, nil
}

// Built reports whether a real frontend build is embedded, rather than the
// placeholder. Startup logs this so an operator is not left wondering why the UI
// looks unfinished.
func (h *Handler) Built() bool {
	_, err := fs.Stat(h.files, "assets")
	return err == nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := path.Clean("/" + r.URL.Path)

	for _, prefix := range h.apiPrefixes {
		if strings.HasPrefix(upath, prefix) {
			h.notFound.ServeHTTP(w, r)
			return
		}
	}

	if upath == "/" || upath == "/index.html" {
		h.serveIndex(w, r)
		return
	}

	file, err := h.files.Open(strings.TrimPrefix(upath, "/"))
	if err != nil {
		// Any unknown path is a client-side route, so the SPA handles it. This is
		// what makes a deep link such as /settings/appearance work on reload.
		h.serveIndex(w, r)
		return
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		h.serveIndex(w, r)
		return
	}

	// Vite emits content-hashed asset names, so those are immutable and can be
	// cached hard. Anything else is revalidated, because a stale HTML shell
	// pointing at deleted assets produces a blank page after an upgrade.
	if strings.HasPrefix(upath, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	if seeker, ok := file.(io.ReadSeeker); ok {
		http.ServeContent(w, r, info.Name(), info.ModTime(), seeker)
		return
	}
	_, _ = io.Copy(w, file)
}

func (h *Handler) serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The shell must never be cached: it carries the asset hashes, so a stale copy
	// survives an upgrade and loads files that no longer exist.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.index)
}
