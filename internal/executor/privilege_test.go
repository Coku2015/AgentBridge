package executor

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Coku2015/agentbridge/internal/executor/templates"
)

type privilegeSession struct {
	run       func(string) ([]byte, error)
	protected func(string, []byte, bool) ([]byte, error)
	commands  []string
}

func (s *privilegeSession) Run(_ context.Context, cmd string) ([]byte, error) {
	s.commands = append(s.commands, cmd)
	return s.run(cmd)
}
func (s *privilegeSession) RunWithSecret(_ context.Context, cmd string, secret []byte, pty bool) ([]byte, error) {
	s.commands = append(s.commands, cmd)
	return s.protected(cmd, secret, pty)
}
func (s *privilegeSession) Upload(context.Context, io.Reader, string) (string, error) { return "", nil }
func (s *privilegeSession) Close() error                                              { return nil }

func TestResolvePrivilegeRoot(t *testing.T) {
	s := &privilegeSession{run: func(string) ([]byte, error) { return []byte("0\n"), nil }}
	got, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true})
	if err != nil || got.Mode != templates.PrivRoot {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestResolvePrivilegeNOPASSWD(t *testing.T) {
	s := &privilegeSession{run: func(cmd string) ([]byte, error) {
		if cmd == "id -u" {
			return []byte("1000\n"), nil
		}
		return []byte("0\n"), nil
	}}
	got, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true})
	if err != nil || got.Mode != templates.PrivSudoNOP {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestResolvePrivilegeSudoPasswordUsesProtectedStdin(t *testing.T) {
	password := []byte("account-sudo-secret")
	s := &privilegeSession{
		run: func(cmd string) ([]byte, error) {
			if cmd == "id -u" {
				return []byte("1000\n"), nil
			}
			return nil, errors.New("sudo: a password is required")
		},
		protected: func(cmd string, secret []byte, pty bool) ([]byte, error) {
			if pty || string(secret) != string(password) {
				t.Fatalf("protected sudo did not receive the account password through stdin")
			}
			if strings.Contains(cmd, string(password)) {
				t.Fatal("sudo password leaked into command")
			}
			return []byte("0\r\n"), nil
		},
	}
	got, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true, SudoPassword: password})
	if err != nil || got.Mode != templates.PrivSudoPassword {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestResolvePrivilegeSudoPasswordRetriesWithPTYWhenPolicyRequiresIt(t *testing.T) {
	attempts := 0
	s := &privilegeSession{
		run: func(cmd string) ([]byte, error) {
			if cmd == "id -u" {
				return []byte("1000\n"), nil
			}
			return nil, errors.New("sudo: a password is required")
		},
		protected: func(_ string, _ []byte, pty bool) ([]byte, error) {
			attempts++
			if attempts == 1 {
				if pty {
					t.Fatal("first sudo password attempt should use plain stdin")
				}
				return []byte("sudo: sorry, you must have a tty to run sudo"), errors.New("exit 1")
			}
			if !pty {
				t.Fatal("legacy requiretty retry did not request a PTY")
			}
			return []byte("0\r\n"), nil
		},
	}
	got, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true, SudoPassword: []byte("secret")})
	if err != nil || got.Mode != templates.PrivSudoPassword || attempts != 2 {
		t.Fatalf("result=%+v attempts=%d err=%v", got, attempts, err)
	}
}

func TestResolvePrivilegeAddsValidatedSudoersDropIn(t *testing.T) {
	rootPassword := []byte("root-secret")
	s := &privilegeSession{
		run: func(cmd string) ([]byte, error) {
			if cmd == "id -u" {
				return []byte("1001\n"), nil
			}
			return []byte("0\n"), nil
		},
		protected: func(cmd string, secret []byte, pty bool) ([]byte, error) {
			if !pty || string(secret) != string(rootPassword) {
				t.Fatal("sudoers update did not use protected root-password stdin")
			}
			if strings.Contains(cmd, "printf AB_ROOT_OK") {
				return []byte("AB_ROOT_OK"), nil
			}
			for _, want := range []string{"/etc/sudoers.d/agentbridge-${uid}", "visudo -cf", "chmod 0440", "mv -f"} {
				if !strings.Contains(cmd, want) {
					t.Fatalf("sudoers command missing %q: %s", want, cmd)
				}
			}
			if strings.Contains(cmd, string(rootPassword)) {
				t.Fatal("root password leaked into command")
			}
			return nil, nil
		},
	}
	got, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true, AddToSudoers: true, RootPassword: rootPassword})
	if err != nil || got.Mode != templates.PrivSudoNOP || !got.ConfiguredSudoers {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestResolvePrivilegeFallsBackToSu(t *testing.T) {
	s := &privilegeSession{
		run: func(cmd string) ([]byte, error) {
			if cmd == "id -u" {
				return []byte("1000\n"), nil
			}
			return nil, errors.New("sudo unavailable")
		},
		protected: func(cmd string, _ []byte, _ bool) ([]byte, error) {
			if !strings.HasPrefix(cmd, "su - root -c ") {
				t.Fatalf("expected su command, got %s", cmd)
			}
			return []byte("0\r\n"), nil
		},
	}
	got, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true, UseSuFallback: true, RootPassword: []byte("root-secret")})
	if err != nil || got.Mode != templates.PrivSu || !got.UsedSuFallback {
		t.Fatalf("result=%+v err=%v", got, err)
	}
}

func TestResolvePrivilegeRequiresSudoPassword(t *testing.T) {
	s := &privilegeSession{run: func(cmd string) ([]byte, error) {
		if cmd == "id -u" {
			return []byte("1000\n"), nil
		}
		return nil, errors.New("sudo: a password is required")
	}}
	_, err := ResolvePrivilege(context.Background(), s, PrivilegeRequest{Elevate: true})
	if code := PrivilegeErrorCode(err); code != "sudo_password_required" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}
