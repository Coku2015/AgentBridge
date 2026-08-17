<p align="center">
  <img src="assets/agentbridge-banner.png" alt="AgentBridge — secure bridge between VBR and Windows/Linux hosts" width="100%">
</p>

<h1 align="center">AgentBridge</h1>

<p align="center"><strong>Bootstrap once. Trust by certificate. Manage with Veeam.</strong></p>

<p align="center">
  English · <a href="README-CN.md">简体中文</a>
</p>

---

## What is AgentBridge?

AgentBridge is a cross-platform bootstrap and enrollment tool for **Veeam Backup & Replication (VBR)**. Run one self-contained application directly on your Windows, Linux, or macOS management machine—no service installation or external runtime required.

It helps backup teams bring **Windows and Linux hosts** into VBR safely: deploy the Veeam Deployment Kit where needed, optionally pre-install a matched Veeam Agent on Linux, then create a certificate-based Protection Group for VBR discovery and ongoing management.

AgentBridge handles the first trusted connection. Backup policies, scheduled backups, upgrades, restores, and long-term lifecycle management remain with VBR.

## Why AgentBridge?

| Principle | Capability | What it means |
|---|---|---|
| portable | **Run it where you work** | A self-contained application for Windows, Linux, and macOS. Start it directly and manage the workflow in your browser. |
| bridge | **Mixed-host onboarding** | Prepare Windows and Linux hosts in one workflow, then enroll them in a shared certificate-based Protection Group. |
| shield | **No stored privileged credentials** | SSH, Windows administrator, and VBR credentials are used only for the active operation—not kept as long-term records. |
| check | **Validate before enrollment** | Linux hosts are probed and matched to the right payload; Windows hosts are preflighted for SMB, admin shares, and Task Scheduler RPC. |
| package | **Use your own VBR as the source** | Deployment Kits and Linux Agent payloads come from your VBR—not from an AgentBridge package repository. |
| laptop | **Remote or operator-led deployment** | Deploy remotely when access is approved, or generate a short-lived manual install command for restricted environments. |
| layers | **Honest status, not one green light** | Local installation, Protection Group creation, and VBR discovery are reported as separate outcomes. |

## Supported today

| Endpoint | What AgentBridge deploys | Methods |
|---|---|---|
| Linux | Deployment Kit, or Agent + Deployment Kit | SSH as root or with automatic sudo/su privilege elevation; manual pull install |
| Windows | **Deployment Kit** | SMB 3 + Task Scheduler RPC; short-lived manual pull install |

On Windows, VBR deploys the Veeam Agent according to the Protection Group configuration after the rescan. AgentBridge does not currently select or install Windows Agent packages directly.

## Before you begin

You will need:

- A reachable **Veeam Backup & Replication v13.1** environment;
- A Windows, Linux, or macOS machine to run AgentBridge;
- SSH access to Linux, or a Linux administrator who can run the manual install locally;
- A Windows administrator account and access to TCP/445, `ADMIN$`, and Task Scheduler RPC for remote Windows deployment;
- Network connectivity from VBR to the endpoints for the later rescan stage.

## Quick start

1. Download the AgentBridge build for your Windows, Linux, or macOS management machine from **Releases**, then run it without arguments:

   ```bash
   agentbridge
   ```

   AgentBridge prints a concise English startup banner with its name, purpose, browser addresses and running state, then opens the local Web Console automatically. Diagnostic logs remain in `data/logs/agentbridge.log`. If the browser does not open, copy one of the displayed addresses into it. The former `agentbridge serve` command remains available as a compatibility alias.

2. Connect to VBR in the console. AgentBridge pins the server certificate on first use, then generates or imports a Deployment Kit.

3. Add hosts and deploy:

   - **Linux** — test the credentials, confirm the recommended Agent profile when required, then install the Kit or Agent + Kit.
   - **Windows** — run the remote preflight and install the Deployment Kit, or copy the short-lived manual-install command to an administrator session on the host.
   - Select ready hosts, create a certificate-based `Individual Computers` Protection Group, and wait for the VBR rescan.

Release tags and downloadable binaries are produced by the
[GitHub Release workflow](.github/workflows/release.yml). The Git tag is the version shown by the
binary; for example, tag `v0.1.0` produces `AgentBridge v0.1.0`.

## See the workflow

### 1. Connect to VBR and prepare deployment components

<img src="assets/screenshots/connect-en.png" alt="AgentBridge connected to VBR with Deployment Kit ready" width="100%">

### 2. Add Windows and Linux hosts

<img src="assets/screenshots/hosts-en.png" alt="AgentBridge host list for Linux SSH and Windows SMB/RPC deployment" width="100%">

### 3. Create a certificate-based Protection Group

<img src="assets/screenshots/protection-group-en.png" alt="AgentBridge creating a certificate-based Protection Group" width="100%">

## Choose a deployment path

| Situation | Recommended path |
|---|---|
| Backup team has approved temporary Linux access | Remote SSH deployment |
| Linux team does not share SSH/root credentials | Generate a manual command for the Linux administrator |
| A Windows administrator account is available and SMB/RPC is allowed | Remote Windows deployment |
| Admin shares are unavailable or Remote UAC blocks remote deployment | Generate a short-lived manual-install command for the endpoint administrator |

## Important boundaries

- AgentBridge is not a replacement for VBR. It does not create backup jobs, run restores, or manage the Agent lifecycle over time.
- A compatibility recommendation for an unsupported Linux distribution is not Veeam vendor support. Validate it in a lab first.
- Creating a new Deployment Kit campaign can invalidate the temporary certificates in an older, unpaired Kit. Plan campaigns before a large rollout.
- “Installed locally” and “discovered by VBR” are independent outcomes. Use the layered status in the console to diagnose the next action.

## Help and contributions

Issues, use cases, and improvements are welcome through GitHub Issues. When reporting a problem, include redacted errors, endpoint platform, VBR version, and reproduction steps. Never include passwords, private keys, tokens, or Deployment Kit contents.
