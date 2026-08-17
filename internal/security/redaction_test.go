package security

import "testing"

func TestIsSecretFieldName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"password", true},
		{"Password", true},
		{"adminPassword", true},
		{"privateKey", true},
		{"bearerToken", true},
		{"api_key", true},
		{"passphrase", true},
		// Non-secret structural fields MUST be preserved.
		{"server", false},
		{"port", false},
		{"username", false},
		{"hostName", false},
		{"productVersion", false},
		{"apiRevision", false},
	}
	for _, c := range cases {
		if got := IsSecretFieldName(c.name); got != c.want {
			t.Errorf("IsSecretFieldName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScrubber(t *testing.T) {
	s := NewScrubber()
	s.Add("s3cr3t")
	s.Add("") // ignored
	out := s.Scrub("connect with s3cr3t now")
	want := "connect with [REDACTED] now"
	if out != want {
		t.Fatalf("Scrub = %q, want %q", out, want)
	}

	// Multiple distinct secrets are each masked.
	s.Add("tok-123")
	out = s.Scrub("tok-123 and s3cr3t")
	if out != "[REDACTED] and [REDACTED]" {
		t.Fatalf("Scrub multi = %q", out)
	}

	// No-registered-secret scrubber passes text through unchanged.
	if NewScrubber().Scrub("plain") != "plain" {
		t.Fatal("empty scrubber altered input")
	}
}

func TestSanitizeMap(t *testing.T) {
	in := map[string]any{
		"server":   "vbr.example",
		"port":     9419,
		"password": "hunter2",
		"nested": map[string]any{
			"token":    "abc",
			"keepThis": "yes",
			"deep": map[string]any{
				"privateKey": "PK",
			},
		},
	}
	out := SanitizeMap(in)
	if out["server"] != "vbr.example" {
		t.Errorf("server altered: %v", out["server"])
	}
	if out["password"] != Redacted {
		t.Errorf("password not redacted: %v", out["password"])
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested not a map")
	}
	if nested["token"] != Redacted {
		t.Errorf("nested token not redacted: %v", nested["token"])
	}
	if nested["keepThis"] != "yes" {
		t.Errorf("keepThis altered: %v", nested["keepThis"])
	}
	deep, _ := nested["deep"].(map[string]any)
	if deep["privateKey"] != Redacted {
		t.Errorf("deep privateKey not redacted: %v", deep["privateKey"])
	}
}

func TestFingerprintStable(t *testing.T) {
	// Same bytes -> same fingerprint, in the documented AB:CD format.
	fp := Fingerprint([]byte("hello"))
	if len(fp) == 0 || fp[2] != ':' {
		t.Fatalf("unexpected fingerprint format %q", fp)
	}
	if Fingerprint([]byte("hello")) != fp {
		t.Fatal("fingerprint not stable for identical input")
	}
	if Fingerprint([]byte("hello")) == Fingerprint([]byte("world")) {
		t.Fatal("distinct inputs produced identical fingerprints")
	}
}
