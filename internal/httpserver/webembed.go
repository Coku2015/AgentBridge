package httpserver

import "embed"

// dist holds the embedded Web UI produced by `npm run build` (Vite) into
// internal/httpserver/web/dist. The placeholder .gitkeep guarantees the
// directory exists before the first frontend build, so a clean checkout still
// compiles; `make web` overwrites it with the real bundle.
//
// Use `make web-dev` during development for HMR against the Go API.
//
//go:embed all:web/dist
var dist embed.FS
