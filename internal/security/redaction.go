package security

import (
	"encoding/json"
	"strings"
	"sync"
)

// Redacted is the placeholder substituted for any secret value before it can
// reach persisted state or logs (Constitution Principle II, red line 1).
const Redacted = "[REDACTED]"

// secretFieldMarkers names (case-insensitive substrings) that mark a field as
// holding a secret. The list is intentionally conservative: over-redacting a
// non-secret is safe; leaking a secret is not.
var secretFieldMarkers = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"passphrase",
	"privatekey",
	"private_key",
	"bearer",
	"apikey",
	"api_key",
}

// IsSecretFieldName reports whether a struct/JSON field name denotes a secret.
// storage uses this as the persistence deny-list gate (red line 1).
func IsSecretFieldName(name string) bool {
	n := strings.ToLower(name)
	for _, m := range secretFieldMarkers {
		if strings.Contains(n, m) {
			return true
		}
	}
	return false
}

// Scrubber masks known secret literal values out of arbitrary text such as log
// lines and error messages. It holds only in-memory references and never
// persists them. Safe for concurrent use.
type Scrubber struct {
	mu      sync.Mutex
	secrets []string
}

// NewScrubber returns an empty Scrubber.
func NewScrubber() *Scrubber { return &Scrubber{} }

// Add registers a secret literal to be masked. Empty values are ignored.
func (s *Scrubber) Add(secret string) {
	if secret == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = append(s.secrets, secret)
}

// Scrub returns in with every registered secret literal replaced by Redacted.
// If no secrets are registered it returns in unchanged.
func (s *Scrubber) Scrub(in string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := in
	for _, sec := range s.secrets {
		if sec != "" && strings.Contains(out, sec) {
			out = strings.ReplaceAll(out, sec, Redacted)
		}
	}
	return out
}

// SanitizeMap returns a copy of m in which every secret-named key (at any depth)
// has its value replaced by Redacted. Non-secret keys are preserved. Used before
// any write to persisted storage so secrets can never be journaled.
func SanitizeMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if IsSecretFieldName(k) {
			out[k] = Redacted
			continue
		}
		out[k] = sanitizeValue(v)
	}
	return out
}

func sanitizeValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return SanitizeMap(val)
	case []any:
		res := make([]any, len(val))
		for i, item := range val {
			res[i] = sanitizeValue(item)
		}
		return res
	default:
		return v
	}
}

// SanitizeJSON unmarshals a JSON object, redacts secret-named fields, and
// re-marshals it. Non-object input is returned unchanged.
func SanitizeJSON(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Not a JSON object: return as-is (no structural secrets to redact).
		return raw, nil
	}
	return json.Marshal(SanitizeMap(m))
}
