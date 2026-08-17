package httpserver

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
)

var launchBrowser = openDefaultBrowser

func accessURLs(addr string, secure bool) (string, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		if hostname, hostnameErr := os.Hostname(); hostnameErr == nil && hostname != "" {
			host = hostname
		} else {
			host = "localhost"
		}
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	primary := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port), Path: "/"}).String()
	if !secure && (host == "127.0.0.1" || host == "::1") {
		alternative := (&url.URL{Scheme: scheme, Host: net.JoinHostPort("localhost", port), Path: "/"}).String()
		return primary, alternative
	}
	return primary, ""
}

func openDefaultBrowser(rawURL string) error {
	name, args, err := browserCommand(runtime.GOOS, rawURL)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("find browser launcher %s: %w", name, err)
	}
	cmd := exec.Command(path, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start browser launcher: %w", err)
	}
	return cmd.Process.Release()
}

func browserCommand(goos, rawURL string) (string, []string, error) {
	switch goos {
	case "darwin":
		return "open", []string{rawURL}, nil
	case "windows":
		return "rundll32.exe", []string{"url.dll,FileProtocolHandler", rawURL}, nil
	case "linux":
		return "xdg-open", []string{rawURL}, nil
	default:
		return "", nil, errors.New("automatic browser opening is not supported on this platform")
	}
}
