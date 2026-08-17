package packages

import (
	"context"
	"testing"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

type fakeLister struct {
	pkgs  []vbr.AgentPackage
	calls int
}

func (f *fakeLister) ListLinuxAgentPackages(_ context.Context) ([]vbr.AgentPackage, error) {
	f.calls++
	return f.pkgs, nil
}

func TestCatalogListCaches(t *testing.T) {
	l := &fakeLister{pkgs: []vbr.AgentPackage{{Name: "veeamagent", Distribution: "rhel", Architecture: "x64"}}}
	c := NewCatalog(l)
	p1, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 1 || p1[0].Name != "veeamagent" {
		t.Fatalf("list = %+v", p1)
	}
	// Second call must hit the cache (no new VBR call).
	if _, err := c.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.calls != 1 {
		t.Fatalf("want 1 list call (cached), got %d", l.calls)
	}
}

func TestCatalogRefreshRefetches(t *testing.T) {
	l := &fakeLister{pkgs: []vbr.AgentPackage{{Name: "veeamagent"}}}
	c := NewCatalog(l)
	_, _ = c.List(context.Background())
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.calls != 2 {
		t.Fatalf("refresh must re-fetch; calls = %d", l.calls)
	}
}
