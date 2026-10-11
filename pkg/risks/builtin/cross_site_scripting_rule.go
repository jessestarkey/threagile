package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type CrossSiteScriptingRule struct{}

func NewCrossSiteScriptingRule() *CrossSiteScriptingRule {
	return &CrossSiteScriptingRule{}
}

func (*CrossSiteScriptingRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "cross-site-scripting",
		Title: "Cross-Site Scripting (XSS)",
		Description: "For each web application Cross-Site Scripting (XSS) risks might arise. In terms " +
			"of the overall risk level take other applications running on the same domain into account as well.",
		Impact:     "If this risk remains unmitigated, attackers might be able to access individual victim sessions and steal or modify user data.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		Action: "Apply context-aware output encoding through an auto-escaping template engine, eliminate unsafe DOM sinks, and " +
			"deploy a strict nonce- or hash-based Content Security Policy.",
		Mitigation: "Render all dynamic content through a template engine or framework with contextual auto-escaping enabled " +
			"(React, Angular, Jinja2 autoescape, Razor), and prohibit escape-bypass constructs such as " +
			"dangerouslySetInnerHTML, bypassSecurityTrustHtml, the Jinja safe filter, or Html.Raw unless the value has " +
			"first passed through a vetted HTML sanitizer such as DOMPurify. Encode for the output context: HTML body, " +
			"HTML attribute, JavaScript string, CSS, and URL each need different encoding, and URLs written into href or " +
			"src must be validated against an http/https scheme allowlist to block javascript: URIs. In client-side code, " +
			"do not write untrusted data to innerHTML, outerHTML, document.write, eval, string-argument setTimeout, or " +
			"location; use textContent and safe DOM APIs, and enforce Trusted Types where supported. Deploy a strict " +
			"Content Security Policy with per-response nonces or hashes and strict-dynamic, no unsafe-inline or " +
			"unsafe-eval, plus object-src none and base-uri none, rolled out first in report-only mode. Mark session " +
			"cookies HttpOnly so injected script cannot read them, and serve user-uploaded content from a separate " +
			"sandboxed origin. For third-party products, confirm the vendor's encoding and CSP posture and keep the " +
			"product patched. References: CWE-79; CAPEC-63 (Cross-Site Scripting); OWASP Top 10:2025 A05 (Injection).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web applications.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed in the web application.",
		FalsePositives: "When the technical asset " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        79,
	}
}

func (*CrossSiteScriptingRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossSiteScriptingRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		risks = append(risks, r.createRisk(input, technicalAsset))
	}
	return risks, nil
}

func (asl CrossSiteScriptingRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.WebApplication) // TODO: also mobile clients or rich-clients as long as they use web-view...
}

func (r *CrossSiteScriptingRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Cross-Site Scripting (XSS)</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact intentionally stays keyed off both Confidentiality and Integrity rather than
	// narrowing to just Integrity (this category's own STRIDE value): per this category's own
	// Impact text, a successful XSS lets an attacker "steal or modify" victim data -- both a
	// confidentiality and an integrity consequence, not just the latter.
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood := computeLikelihood(types.VeryLikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
