# `rules/` — built-in package matching rules

This directory holds AgentBridge's **embedded, versioned, testable** package
matching rules.

## Principles

- Rules are **data** (versioned, unit-tested), never sprinkled across UI or shell.
- Every recommendation is **explanatory**: it carries evidence, confidence,
  warnings and unmet conditions (AB-FR-101).
- A non-official OS match **must** require explicit user confirmation
  (AB-FR-103). A user override is allowed and audited, but is never re-labelled
  as `VendorSupported` or `LabValidated`.
- `CompatibilityInferred` means AgentBridge mapped the target to an upstream
  RPM/DEB family (for example CentOS → RHEL or Mint → Debian). It is an
  installation hypothesis, not a Veeam support statement and not a lab result.
- MVP uses **local static rules only** — no cloud dependency (AB-FR-107).

## Rule levels (§15.3)

| Level | Meaning |
|---|---|
| `VendorSupported` | Matches the current official Veeam support matrix. |
| `LabValidated` | Installed + discovered + backed up + restored in this project's lab. |
| `CompatibilityInferred` | Upstream-family package inference; always confirmation-required. |
| `UserSelected` | User overrode the recommendation; no project validation claim. |
| `Blocked` | Known hard miss (architecture, glibc, package format, …). |

> Reserved for M3 (Probe & Matcher). Layout and schema will be finalized when
> the matcher lands.

## Agent 13 repository baseline

The package selector is aligned with the directory and payload layout in the
official [Veeam Agent 13 repository](https://repository.veeam.com/backup/linux/agent-13/).
The repository currently contains historical 13.0 builds plus 13.1.0.252 and
13.1.1.4; the selector chooses the version supplied by the VBR export and does
not mix versions.

| Repository family | Standard set | No-snapshot set | Architectures |
|---|---|---|---|
| `rpm/el/7` | `kmod-veeamsnap + veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `x86_64` |
| `rpm/el/8` | `kmod-veeamsnap + veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `x86_64`; `ppc64le` is nosnap-only |
| `rpm/el/9`, `rpm/el/10` | `kmod-blksnap + veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `x86_64`; `ppc64le` is nosnap-only |
| `rpm/sles/SLE_12_SP5` | `veeamsnap-kmp-default + veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `x86_64`; `ppc64le` is nosnap-only |
| `rpm/sles/SLE_15_SP3` | `blksnap-kmp-default` or `blksnap-kmp-preempt` + `veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `x86_64`; `ppc64le` is nosnap-only |
| `rpm/sles/SLE_15_SP4–SP7`, `SLE_16` | `blksnap-kmp-default + veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `x86_64`; `ppc64le` is nosnap-only |
| Debian/Ubuntu DEB repository | Debian 10 and older: `veeamsnap + veeam-libs + veeam`; Debian 11+/Ubuntu 22+: `blksnap + veeam-libs + veeam` | `veeam-libs + veeam-nosnap` | `amd64` only |

`veeam-release-*` packages are repository bootstrap metadata, not part of the
Agent install set. `veeam-ueficert` is selected only when the target reports
Secure Boot enabled. The repository has no Agent 13 `aarch64` or `s390x`
payload, and no DEB `ppc64le` payload; those targets are blocked instead of
being given a fabricated package recommendation.
