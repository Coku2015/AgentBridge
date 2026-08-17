// Package pg builds Protection Group specifications and drives VBR enrollment:
// create an Individual Computers PG, poll the create session, trigger Rescan
// and verify Discovered Entities (section 13.10, section 12).
//
// Only hosts that passed local install/verification are submitted to VBR
// (AB-FR-180). PG create and Rescan are async and polled via VBR sessions
// (AB-FR-186). operatingSystem showing Unknown/Other is NOT a failure signal —
// the Agent's own status is authoritative (AB-FR-188). A successfully created PG
// records both its VBR id and the AgentBridge job id/tag (AB-FR-190).
package pg
