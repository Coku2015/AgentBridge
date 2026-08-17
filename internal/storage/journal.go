package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/Coku2015/agentbridge/internal/security"
)

// Journal is an append-only, redacted record store for job/batch events. Every
// entry passes security.SanitizeMap before it is written, so secrets can never
// be persisted (Constitution red line 1, AB-FR-024). Format: one JSON object
// per line (JSON Lines).
type Journal struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

// OpenJournal opens (creating if needed) the journal at path. The parent
// directory is created with 0700.
func OpenJournal(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Journal{path: path, f: f}, nil
}

// Append sanitizes entry (redacting any secret-named field) and writes it as a
// JSON line. It never persists secrets.
func (j *Journal) Append(entry map[string]any) error {
	safe := security.SanitizeMap(entry)
	raw, err := json.Marshal(safe)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	_, err = j.f.Write(raw)
	return err
}

// Close flushes and closes the underlying file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	return j.f.Close()
}

// Store is a small redacted key/value store persisted as JSON, keyed by
// collection and key. Only non-secret fields are stored: every value is
// sanitized before write (red line 1).
type Store struct {
	path string
	mu   sync.Mutex
	data map[string]map[string]any
}

// OpenStore loads (or creates) the store at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]map[string]any{}}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, err
	}
	return s, nil
}

// Put sanitizes value and persists it under collection/key.
func (s *Store) Put(collection, key string, value map[string]any) error {
	safe := security.SanitizeMap(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[collection] == nil {
		s.data[collection] = map[string]any{}
	}
	s.data[collection][key] = safe
	return s.flushLocked()
}

// Get returns the stored value for collection/key and whether it existed.
func (s *Store) Get(collection, key string) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data[collection]
	if !ok {
		return nil, false
	}
	v, ok := c[key]
	if !ok {
		return nil, false
	}
	m, _ := v.(map[string]any)
	return m, true
}

func (s *Store) flushLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
