package packages

import (
	"context"
	"fmt"
	"sync"

	"github.com/Coku2015/agentbridge/internal/vbr"
)

// Lister lists Linux Agent packages from VBR. *vbr.RESTAdapter satisfies it
// structurally; the catalog never names RESTAdapter (SOLID-D).
type Lister interface {
	ListLinuxAgentPackages(ctx context.Context) ([]vbr.AgentPackage, error)
}

// Catalog lists Linux Agent packages from VBR, caching the listing in memory for
// the process lifetime (re-fetch via Refresh). It holds no secrets. Artifact
// downloads are handled separately by ArtifactStore because the catalog and
// the PreInstalledAgents export workflow have different lifecycles.
type Catalog struct {
	mu     sync.Mutex
	lister Lister
	cache  []vbr.AgentPackage
}

// NewCatalog builds a Catalog over a VBR lister.
func NewCatalog(l Lister) *Catalog { return &Catalog{lister: l} }

// List returns the package catalog, fetching from VBR on first call (FR-007).
func (c *Catalog) List(ctx context.Context) ([]vbr.AgentPackage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache != nil {
		return c.cache, nil
	}
	pkgs, err := c.lister.ListLinuxAgentPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("packages: list: %w", err)
	}
	c.cache = pkgs
	return pkgs, nil
}

// Refresh forces a re-fetch from VBR.
func (c *Catalog) Refresh(ctx context.Context) ([]vbr.AgentPackage, error) {
	c.mu.Lock()
	c.cache = nil
	c.mu.Unlock()
	return c.List(ctx)
}
