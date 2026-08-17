package sshtransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Auth carries memory-only SSH credentials (AB-FR-024). Password, private key
// and passphrase are never persisted or logged. Only one method need be set.
type Auth struct {
	Password      string // memory-only
	PrivateKeyPEM []byte // memory-only
	Passphrase    string // memory-only
}

// Config identifies a target and its trust state. Secrets live only in Auth.
// PinnedHostKey MUST be set: first connect requires the operator to have
// captured + confirmed the key (red line 4). There is deliberately no
// "InsecureIgnoreHostKey" field.
type Config struct {
	Host string
	Port int
	User string

	PinnedHostKey ssh.PublicKey // from CaptureHostKey + operator confirmation

	Auth    Auth
	Timeout time.Duration
}

// Client is a connected pure-Go SSH session. Secrets are held only in the
// underlying ssh.ClientConfig (in memory) and never escape the process.
type Client struct {
	cfg  *ssh.ClientConfig
	addr string
	conn *ssh.Client
}

// Dial establishes a pinned-host-key SSH connection. It fails fast if no key is
// pinned (red line 4) or if the presented key differs from the pin.
func Dial(ctx context.Context, c Config) (*Client, error) {
	if c.PinnedHostKey == nil {
		return nil, errors.New("sshtransport: no pinned host key — capture and confirm the host key first (AB-FR-121)")
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	authMethods, err := buildAuth(c.Auth)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            authMethods,
		HostKeyCallback: pinnedCallback(c.PinnedHostKey), // enforced by ssh.FixedHostKey
		Timeout:         c.Timeout,
	}
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, redactDialErr(err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, redactDialErr(err)
	}
	return &Client{cfg: cfg, addr: addr, conn: ssh.NewClient(sshConn, chans, reqs)}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Addr returns the dialed host:port (non-secret).
func (c *Client) Addr() string { return c.addr }

// Run executes cmd and returns combined stdout/stderr. On failure the combined
// output is appended to the error (tail-bounded): command diagnostics such as
// the kit installer's own error message are what makes an exit code actionable.
// Output of these fixed-template commands contains no credentials.
func (c *Client) Run(ctx context.Context, cmd string) ([]byte, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out, err := combinedOutputContext(ctx, sess, cmd)
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return out, fmt.Errorf("sshtransport: run: %w; output: %s", err, tail(msg, 2048))
		}
		return out, fmt.Errorf("sshtransport: run: %w", err)
	}
	return out, nil
}

// RunWithSecret executes a fixed-template command while supplying a secret on
// stdin. A PTY can be requested for sudo/su policies that require a terminal;
// terminal echo is disabled so the password cannot appear in output or logs.
// The caller retains ownership of secret. This method copies and wipes its
// temporary buffer before returning.
func (c *Client) RunWithSecret(ctx context.Context, cmd string, secret []byte, requestPTY bool) ([]byte, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	if requestPTY {
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		if err := sess.RequestPty("xterm", 40, 80, modes); err != nil {
			return nil, fmt.Errorf("sshtransport: request protected terminal: %w", err)
		}
	}

	// Supply the password plus two empty lines. sudo commonly permits three
	// attempts; on a PTY, sending only one line leaves a wrong-password probe
	// blocked waiting for attempts two and three because channel EOF is not a
	// terminal EOF. Empty follow-up attempts make that failure deterministic.
	// A successful first attempt leaves only harmless blank input for the fixed
	// non-interactive command.
	input := make([]byte, len(secret)+3)
	copy(input, secret)
	for i := len(secret); i < len(input); i++ {
		input[i] = '\n'
	}
	defer func() {
		for i := range input {
			input[i] = 0
		}
	}()

	// Older su/PAM implementations (notably CentOS 7) flush terminal input just
	// before displaying their password prompt. Feeding the secret immediately
	// therefore loses it and leaves su waiting forever. PTY-backed commands use
	// a short delayed reader so the password is delivered after that flush. The
	// context-aware runner closes the SSH session if the caller cancels.
	delay := time.Duration(0)
	if requestPTY {
		delay = 500 * time.Millisecond
	}
	sess.Stdin = &delayedReader{
		ctx:    ctx,
		delay:  delay,
		reader: bytes.NewReader(input),
	}
	out, err := combinedOutputContext(ctx, sess, cmd)
	out = redactOutputSecret(out, secret)
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return out, fmt.Errorf("sshtransport: protected run: %w; output: %s", err, tail(msg, 2048))
		}
		return out, fmt.Errorf("sshtransport: protected run: %w", err)
	}
	return out, nil
}

// tail returns at most the last n characters of s, prefixed with an ellipsis
// when truncated (installer errors usually sit at the end of the output).
func tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n:])
}

type commandResult struct {
	out []byte
	err error
}

// combinedOutputContext makes ssh.Session execution cancellable. The upstream
// CombinedOutput API has no context parameter, so cancellation must close the
// session to unblock Wait and its stdin/stdout copy goroutines.
func combinedOutputContext(ctx context.Context, sess *ssh.Session, cmd string) ([]byte, error) {
	done := make(chan commandResult, 1)
	go func() {
		out, err := sess.CombinedOutput(cmd)
		done <- commandResult{out: out, err: err}
	}()

	select {
	case result := <-done:
		return result.out, result.err
	case <-ctx.Done():
		_ = sess.Close()
		select {
		case result := <-done:
			return result.out, fmt.Errorf("sshtransport: command canceled: %w", ctx.Err())
		case <-time.After(2 * time.Second):
			return nil, fmt.Errorf("sshtransport: command canceled: %w", ctx.Err())
		}
	}
}

// delayedReader postpones the first read only. It is used for PTY password
// prompts that discard input already buffered before PAM is ready to read it.
type delayedReader struct {
	ctx     context.Context
	delay   time.Duration
	reader  *bytes.Reader
	started bool
}

func (r *delayedReader) Read(p []byte) (int, error) {
	if !r.started {
		r.started = true
		if r.delay > 0 {
			timer := time.NewTimer(r.delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			}
		}
	}
	return r.reader.Read(p)
}

func redactOutputSecret(out, secret []byte) []byte {
	if len(out) == 0 || len(secret) == 0 {
		return out
	}
	return bytes.ReplaceAll(out, secret, []byte("[REDACTED]"))
}

// RunStdin executes cmd, streaming r into the command's stdin (used by Upload).
// The command is built from fixed templates and is never caller-concatenated
// raw (red line 5; see templates.UploadOpenCmd).
func (c *Client) RunStdin(ctx context.Context, cmd string, r io.Reader) error {
	sess, err := c.conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = r
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	var runErr error
	select {
	case runErr = <-done:
	case <-ctx.Done():
		_ = sess.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		runErr = ctx.Err()
	}
	if runErr != nil {
		return fmt.Errorf("sshtransport: run-stdin: %w", runErr)
	}
	return nil
}

// buildAuth constructs ssh.AuthMethod(s) from memory-only credentials. Private
// key parse errors are wrapped so raw key bytes never reach logs (red line 1).
func buildAuth(a Auth) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(a.PrivateKeyPEM) > 0 {
		var (
			signer ssh.Signer
			err    error
		)
		if a.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(a.PrivateKeyPEM, []byte(a.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(a.PrivateKeyPEM)
		}
		if err != nil {
			return nil, errors.New("sshtransport: private key invalid (parse error redacted)")
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		methods = append(methods, ssh.Password(a.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("sshtransport: no auth method provided (password or private key)")
	}
	return methods, nil
}

// redactDialErr strips SSH banner/auth detail that could carry a secret or
// fingerprint, returning a stable actionable message.
func redactDialErr(err error) error {
	if err == nil {
		return nil
	}
	// Map the common failure classes to operator-actionable text.
	msg := err.Error()
	switch {
	case containsFold(msg, "host key mismatch"), containsFold(msg, "host key changed"):
		return ErrHostKeyMismatch
	case containsFold(msg, "unable to authenticate"), containsFold(msg, "no supported methods"):
		return errors.New("sshtransport: authentication failed (credentials held in memory only)")
	case containsFold(msg, "no such host"), containsFold(msg, "temporary failure in name resolution"):
		return errors.New("sshtransport: host not found")
	case containsFold(msg, "i/o timeout"), containsFold(msg, "deadline exceeded"):
		return errors.New("sshtransport: network timeout")
	case containsFold(msg, "connection refused"):
		return errors.New("sshtransport: connection refused")
	case containsFold(msg, "no route to host"), containsFold(msg, "network is unreachable"), containsFold(msg, "host is down"):
		return errors.New("sshtransport: network unreachable")
	case containsFold(msg, "ssh: handshake"), containsFold(msg, "handshake failed"), containsFold(msg, "connection reset"), strings.EqualFold(strings.TrimSpace(msg), "EOF"):
		return errors.New("sshtransport: ssh handshake failed")
	default:
		return fmt.Errorf("sshtransport: connect failed: details redacted")
	}
}

func containsFold(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexFold(s, sub) >= 0
}
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if equalFoldBytes(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}
func equalFoldBytes(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
