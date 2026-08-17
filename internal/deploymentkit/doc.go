// Package deploymentkit manages the Deployment Kit Campaign lifecycle
// (section 13.4, Spike 2).
//
// A single VBR has at most one AgentBridge active enrollment campaign at a
// time: generating a new Kit invalidates previously-issued temporary
// certificates that have not yet paired (AB-FR-061..063). Therefore Kit
// creation is guarded by a VBR-level mutex, the UI shows a live certificate
// countdown, and re-packing only affects Pending targets, never hosts already
// paired with a long-term certificate (AB-FR-067). Kit files live only in a
// protected temp dir and are deleted when the campaign completes, expires or is
// closed (AB-FR-065). Logs never contain private key material or full bundle
// contents (AB-FR-066).
package deploymentkit
