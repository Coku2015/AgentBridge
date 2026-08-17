// Package deploymentprobe contains the credential-free readiness check used
// after a Deployment Kit is installed manually.
package deploymentprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const DefaultPort = 6160

type Status string

const (
	StatusReady  Status = "ready"
	StatusFailed Status = "failed"
)

type Reason string

const (
	ReasonHostUnresolved     Reason = "host_unresolved"
	ReasonNetworkUnreachable Reason = "network_unreachable"
	ReasonServiceUnavailable Reason = "service_unavailable"
)

type Result struct {
	Status   Status
	Reason   Reason
	Detail   string
	Duration time.Duration
}

// Check opens one TCP connection to the fixed Deployment Kit service port.
// The result deliberately contains a machine-readable reason and keeps the
// underlying error for server-side logging only.
func Check(ctx context.Context, host string, port int) Result {
	started := time.Now()
	if port <= 0 {
		port = DefaultPort
	}
	if host == "" {
		return Result{Status: StatusFailed, Reason: ReasonHostUnresolved, Detail: "host is empty", Duration: time.Since(started)}
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err == nil {
		_ = conn.Close()
		return Result{Status: StatusReady, Duration: time.Since(started)}
	}
	return Result{Status: StatusFailed, Reason: classify(err), Detail: err.Error(), Duration: time.Since(started)}
}

func classify(err error) Reason {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReasonHostUnresolved
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonNetworkUnreachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonNetworkUnreachable
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ETIMEDOUT) {
		return ReasonNetworkUnreachable
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ReasonServiceUnavailable
	}
	return ReasonServiceUnavailable
}
