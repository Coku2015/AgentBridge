// Package config holds the non-secret runtime configuration for AgentBridge.
// It deliberately carries NO secret fields: passwords, keys and tokens live only
// in session memory (Constitution red line 2).
package config

import "net"

// Config is the resolved runtime configuration.
type Config struct {
	Listen         string // default 127.0.0.1:8787
	DataDir        string // jobs, journal, logs
	CacheDir       string // package cache
	MaxConcurrency int    // default 10 (AB-NFR-003)
	TLSCert        string // required for non-loopback Listen
	TLSKey         string
	AdminTokenFile string // required for non-loopback Listen
}

// Default returns the safe localhost configuration. A non-loopback Listen set
// by the caller still requires TLS + admin token (see IsRemote).
func Default() Config {
	return Config{
		Listen:         "127.0.0.1:8787",
		DataDir:        "./data",
		CacheDir:       "./cache",
		MaxConcurrency: 10,
	}
}

// IsLoopback reports whether Listen targets a local-only interface.
func (c Config) IsLoopback() bool {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return false
	}
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// IsRemote reports whether Listen binds a non-loopback address, which requires
// TLS + admin authentication (AB-FR-005, FR-041).
func (c Config) IsRemote() bool { return !c.IsLoopback() }

// RemoteOK reports whether a remote listener is fully configured.
func (c Config) RemoteOK() bool {
	return c.TLSCert != "" && c.TLSKey != "" && c.AdminTokenFile != ""
}
