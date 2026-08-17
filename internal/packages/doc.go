// Package packages reads the Veeam Agent package catalog from the customer's own
// VBR and exports selected Linux RPM/DEB payloads (section 13.3, FR-007/041).
//
// VBR's REST API exposes the package export through a temporary
// PreInstalledAgents Protection Group. ArtifactStore keeps the complete RPM/DEB
// payload set for each catalog selection and discards the XML/readme metadata
// included in VBR's archive. No credentials or bearer tokens are stored here.
package packages
