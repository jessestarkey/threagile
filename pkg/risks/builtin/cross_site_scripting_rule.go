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
		Mitigation: "Render dynamic content through a framework with contextual auto-escaping (React, Angular, Razor, or Jinja2 autoescape), and prohibit bypasses such as dangerouslySetInnerHTML or Html.Raw unless the value first passes a vetted sanitizer such as DOMPurify.\n" +
			"Encode for each output context (HTML body, attribute, JavaScript, CSS, and URL), and allow only the http and https schemes in href and src values.\n" +
			"In client-side code, use textContent and safe DOM APIs instead of innerHTML, document.write, or eval, and enforce Trusted Types where supported.\n" +
			"Deploy a strict Content Security Policy with per-response nonces or hashes, no unsafe-inline or unsafe-eval, and object-src and base-uri set to none, starting in report-only mode.\n" +
			"Mark session cookies HttpOnly, and serve user-uploaded content from a separate sandboxed origin.\n" +
			"For third-party products, confirm the vendor's encoding and CSP posture, and keep the product patched.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		FindingClass:   types.FindingClassControlNotEvidenced,
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
	// Impact: baseline plus the CIA step on the higher of the processed confidentiality and integrity
	// (readAndAlterImpact): injection both reads and alters data.
	impact := readAndAlterImpact(parsedModel, types.MediumImpact, technicalAsset)
	likelihood := computeLikelihood(types.Likely, technicalAsset)
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
