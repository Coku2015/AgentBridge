package main

import (
	"context"
	"testing"

	"github.com/Coku2015/agentbridge/internal/httpserver"
)

func TestRunStartsServerWithoutSubcommand(t *testing.T) {
	original := serveHTTP
	defer func() { serveHTTP = original }()

	var got httpserver.Options
	serveHTTP = func(_ context.Context, opts httpserver.Options) error {
		got = opts
		return nil
	}

	if err := run(nil); err != nil {
		t.Fatalf("run without arguments: %v", err)
	}
	if got.Listen != "127.0.0.1:8787" {
		t.Fatalf("listen = %q, want default listener", got.Listen)
	}
	if got.StatusWriter == nil {
		t.Fatal("CLI must provide a startup status writer")
	}
	if got.ProductVersion != Version {
		t.Fatalf("product version = %q, want %q", got.ProductVersion, Version)
	}
}

func TestRunAcceptsServeFlagsWithoutSubcommand(t *testing.T) {
	original := serveHTTP
	defer func() { serveHTTP = original }()

	var got httpserver.Options
	serveHTTP = func(_ context.Context, opts httpserver.Options) error {
		got = opts
		return nil
	}

	if err := run([]string{"--no-browser", "--listen", "localhost:9876"}); err != nil {
		t.Fatalf("run with server flags: %v", err)
	}
	if got.Listen != "localhost:9876" || !got.NoBrowser {
		t.Fatalf("options = %+v", got)
	}
}

func TestServeAliasRemainsCompatible(t *testing.T) {
	original := serveHTTP
	defer func() { serveHTTP = original }()

	called := false
	serveHTTP = func(_ context.Context, _ httpserver.Options) error {
		called = true
		return nil
	}

	if err := run([]string{"serve", "--no-browser"}); err != nil {
		t.Fatalf("serve alias: %v", err)
	}
	if !called {
		t.Fatal("serve alias did not start the server")
	}
}
