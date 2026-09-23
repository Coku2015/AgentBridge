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
	TLSCert        string // optional; enables HTTPS when paired with TLSKey
	TLSKey         string
	AdminTokenFile string // required for non-loopback Listen
}

// Default returns the safe localhost configuration. A non-loopback Listen set
// by the caller still requires an admin token; TLS is optional (see IsRemote).
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
// admin authentication; TLS is optional (AB-FR-005, FR-041).
func (c Config) IsRemote() bool { return !c.IsLoopback() }

// RemoteOK reports whether remote authentication is configured and any TLS
// certificate/key pair is complete.
func (c Config) RemoteOK() bool {
	return c.AdminTokenFile != "" && ((c.TLSCert == "") == (c.TLSKey == ""))
}
