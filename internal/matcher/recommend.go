package matcher

import "fmt"

// Override records an operator's manual package selection (AB-FR-102). A user
// override is always allowed and auditable, but it is NEVER re-labelled as
// VendorSupported or LabValidated (red line 11, section 15.3). It carries no
// credentials.
type Override struct {
	PackageID string // the operator-chosen package
	Reason    string // free-text justification, non-secret
	User      string // confirming operator identity, non-secret
}

// ApplyOverride turns an operator choice into a UserSelected recommendation. The
// level is hard-coded UserSelected so no downstream layer can mistake it for an
// official or lab-validated match. It still requires explicit confirmation flag
// so the UI surfaces the non-validated nature prominently.
func ApplyOverride(o Override, evidence []string) (Recommendation, RuleLevel) {
	ev := append([]string{}, evidence...)
	who := o.User
	if who == "" {
		who = "(unknown operator)"
	}
	ev = append(ev, fmt.Sprintf("operator override: package %s chosen by %s", o.PackageID, who))
	if o.Reason != "" {
		ev = append(ev, "override reason: "+o.Reason)
	}
	return Recommendation{
		RecommendedPackageID:         o.PackageID,
		Confidence:                   "low",
		Evidence:                     ev,
		Warnings:                     []string{"user-selected — not vendor- or lab-validated"},
		RequiresExplicitConfirmation: true,
	}, UserSelected
}

// IdentityMismatchWarning returns a warning string when the configured host
// identity disagrees with the probed hostname (AB-FR-086), else "". It never
// treats an empty side as a mismatch.
func IdentityMismatchWarning(configured, probed string) string {
	if configured != "" && probed != "" && configured != probed {
		return fmt.Sprintf("identity mismatch: configured host %q differs from probed hostname %q", configured, probed)
	}
	return ""
}
