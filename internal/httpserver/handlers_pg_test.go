package httpserver

import (
	"strings"
	"testing"

	"github.com/Coku2015/agentbridge/internal/pg"
	"github.com/Coku2015/agentbridge/internal/vbr"
)

func TestPGDiscoveryErrorPayloadPreservesVBRMessage(t *testing.T) {
	const message = "testlab Error: System reboot is required to continue installation"
	payload := pgDiscoveryErrorPayload(&pg.ErrRescan{VBRMessage: message})
	if payload["error"] != "protection_group_rescan_failed" || payload["detailSource"] != "vbr" || payload["detail"] != message {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestPGDiscoveryErrorPayloadIncludesPerHostFailures(t *testing.T) {
	const message = "testlab Error: System reboot is required to continue installation"
	payload := pgDiscoveryErrorPayload(&pg.ErrRescan{
		Failures: []vbr.SessionFailure{{Host: "10.10.1.22", Message: message}},
	})
	failures, ok := payload["failures"].([]vbr.SessionFailure)
	if !ok || len(failures) != 1 || failures[0].Host != "10.10.1.22" || failures[0].Message != message {
		t.Fatalf("payload = %#v", payload)
	}
	if payload["detailSource"] != "vbr" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestPGDiscoveryErrorPayloadFallbackContainsNoUUID(t *testing.T) {
	payload := pgDiscoveryErrorPayload(&pg.ErrRescan{})
	rendered := payload["detail"].(string)
	if payload["detailSource"] != "unavailable" {
		t.Fatalf("payload = %#v", payload)
	}
	for _, forbidden := range []string{
		"d1d9bd7c-883e-4742-b210-e7625de8476b",
		"4e592ad7-20cf-4ce4-b854-e2b6037bf0d0",
		"session",
	} {
		if strings.Contains(strings.ToLower(rendered), strings.ToLower(forbidden)) {
			t.Fatalf("fallback exposes %q: %q", forbidden, rendered)
		}
	}
}
