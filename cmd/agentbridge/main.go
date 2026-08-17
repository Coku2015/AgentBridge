// Command agentbridge is the single-binary entry point for AgentBridge, the
// secure bootstrap and enrollment tool for Veeam Agents.
//
// Running the binary without arguments starts the embedded Web UI + HTTP API.
// The explicit `serve` command remains available for backward compatibility:
//
//	agentbridge           run the embedded Web UI + HTTP API
//	agentbridge serve     run the embedded Web UI + HTTP API (compatibility)
//	agentbridge version   print version information
//	agentbridge diagnose  print environment diagnostics
//	agentbridge cache     manage the package cache (list | clear)
//
// The CLI carries NO secrets (AB-FR: secrets never via CLI args); credentials
// are entered in the Web UI and kept only in session memory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/Coku2015/agentbridge/internal/httpserver"
)

const usageText = `usage: agentbridge [serve flags]
       agentbridge <command> [flags]

commands:
  serve      run the Web UI and HTTP API (compatibility alias)
  version    print version information
  diagnose   print environment diagnostics
  cache      manage the package cache (list | clear)

run "agentbridge serve -h" to list the optional server flags`

var serveHTTP = httpserver.Serve

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "agentbridge:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return serveCmd(nil)
	}
	switch args[0] {
	case "serve":
		return serveCmd(args[1:])
	case "version":
		return versionCmd(os.Stdout)
	case "diagnose":
		return diagnoseCmd(os.Stdout)
	case "cache":
		return cacheCmd(args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, usageText)
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			return serveCmd(args)
		}
		return fmt.Errorf("unknown command %q\n%s", args[0], usageText)
	}
}

// serveCmd implements `agentbridge serve`. Defaults to a loopback listener with
// a random session token; remote listeners are rejected unless TLS + admin auth
// are configured (AB-FR-003, AB-FR-005).
func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8787", "listen address")
	dataDir := fs.String("data-dir", "", "data directory for jobs, cache and logs")
	tlsCert := fs.String("tls-cert", "", "TLS certificate path (required for non-loopback --listen)")
	tlsKey := fs.String("tls-key", "", "TLS key path (required for non-loopback --listen)")
	adminTokenFile := fs.String("admin-token-file", "", "file holding the admin bearer token (required for non-loopback --listen)")
	noBrowser := fs.Bool("no-browser", false, "do not open the default browser")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// AB-FR-005: a non-loopback listener MUST NOT expose the management UI in
	// cleartext or without admin authentication.
	if !isLoopback(*listen) && (*tlsCert == "" || *tlsKey == "" || *adminTokenFile == "") {
		return errors.New("remote --listen requires --tls-cert, --tls-key and --admin-token-file")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serveHTTP(ctx, httpserver.Options{
		Listen:         *listen,
		DataDir:        *dataDir,
		TLSCert:        *tlsCert,
		TLSKey:         *tlsKey,
		AdminTokenFile: *adminTokenFile,
		NoBrowser:      *noBrowser,
		StatusWriter:   os.Stdout,
		ProductVersion: Version,
	})
}

func versionCmd(w io.Writer) error {
	fmt.Fprintf(w, "agentbridge %s (commit %s)\n", Version, Commit)
	fmt.Fprintf(w, "  %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "  vbr rest api baseline: %s\n", VBRAPIRevisionBaseline)
	return nil
}

func diagnoseCmd(w io.Writer) error {
	fmt.Fprintf(w, "agentbridge %s (commit %s)\n", Version, Commit)
	fmt.Fprintf(w, "runtime: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "numcpu:  %d\n", runtime.NumCPU())
	if cwd, err := os.Getwd(); err == nil {
		fmt.Fprintf(w, "cwd:     %s\n", cwd)
	}
	fmt.Fprintln(w, "note:    probe of data dir, trusted VBR certs and cache size is TODO (M1)")
	return nil
}

func cacheCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("cache requires a subcommand: list | clear")
	}
	switch args[0] {
	case "list":
		return errors.New("cache list: not implemented yet (M2)")
	case "clear":
		return errors.New("cache clear: not implemented yet (M2)")
	default:
		return fmt.Errorf("cache: unknown subcommand %q", args[0])
	}
}

// isLoopback reports whether addr listens on a local-only interface.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
