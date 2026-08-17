package main

import "github.com/Coku2015/agentbridge/internal/vbr"

// Version is the semantic version of the AgentBridge binary. It is injected at
// build time via -ldflags ("-X .../cmd/agentbridge.Version=...") and defaults
// to "dev" for `go run` / untagged builds.
var Version = "dev"

// Commit is the source revision the binary was built from, injected at build
// time. Defaults to "none".
var Commit = "none"

// VBRAPIRevisionBaseline is the VBR REST API revision AgentBridge is coded
// against (Spike 1 freeze item, plan.md R1). It mirrors vbr.APIRevisionBaseline
// — single source of truth — so `version` and the x-api-version header can never
// drift.
var VBRAPIRevisionBaseline = vbr.APIRevisionBaseline
