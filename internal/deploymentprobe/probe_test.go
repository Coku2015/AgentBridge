package deploymentprobe

import (
	"context"
	"net"
	"testing"
)

func TestCheckReportsReadyForListeningPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	result := Check(context.Background(), "127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	if result.Status != StatusReady {
		t.Fatalf("status = %q, want ready (%s)", result.Status, result.Detail)
	}
	if result.Duration <= 0 {
		t.Fatal("expected a positive duration")
	}
}

func TestCheckReportsServiceUnavailableWhenPortIsClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	result := Check(context.Background(), "127.0.0.1", port)
	if result.Status != StatusFailed || result.Reason != ReasonServiceUnavailable {
		t.Fatalf("result = %#v, want service_unavailable failure", result)
	}
	if result.Detail == "" {
		t.Fatal("expected technical detail for server-side logging")
	}
}

func TestCheckReportsUnresolvedHost(t *testing.T) {
	result := Check(context.Background(), "host-that-cannot-exist.invalid", DefaultPort)
	if result.Status != StatusFailed || result.Reason != ReasonHostUnresolved {
		t.Fatalf("result = %#v, want host_unresolved failure", result)
	}
}
