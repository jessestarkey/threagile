package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type CrossSiteRequestForgeryRule struct{}

func NewCrossSiteRequestForgeryRule() *CrossSiteRequestForgeryRule {
	return &CrossSiteRequestForgeryRule{}
}

func (*CrossSiteRequestForgeryRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "cross-site-request-forgery",
		Title:       "Cross-Site Request Forgery (CSRF)",
		Description: "When a web application is accessed via web protocols Cross-Site Request Forgery (CSRF) risks might arise.",
		Impact: "If this risk remains unmitigated, attackers might be able to trick logged-in victim users into unwanted actions within the web application " +
			"by visiting an attacker controlled web site.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action: "Protect every state-changing request with the framework's synchronizer token or signed double-submit cookie, " +
			"and set SameSite on all session cookies as defense in depth.",
		Mitigation: "Enable the web framework's built-in CSRF protection (synchronizer token pattern, or the signed double-submit " +
			"cookie pattern for stateless applications) and validate the token server-side on every state-changing request " +
			"(POST, PUT, PATCH, DELETE). Never change state on GET or HEAD. Set SameSite=Lax or Strict, Secure, and " +
			"HttpOnly on all session and authentication cookies as an additional layer, not the only control. For APIs " +
			"called from browser JavaScript, authenticate with a bearer token in the Authorization header or require a " +
			"custom request header rather than relying on ambient cookies, and restrict CORS to an explicit origin " +
			"allowlist with no wildcard when credentials are allowed. Verify the Origin or Sec-Fetch-Site header on " +
			"sensitive endpoints, and require re-authentication for high-impact actions such as changing credentials, " +
			"roles, or transfer destinations. For third-party products, confirm the vendor's CSRF protection is enabled " +
			"and keep the product patched. References: CWE-352; CAPEC-62 (Cross Site Request Forgery); OWASP Top 10:2025 " +
			"A01 (Broken Access Control).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope web applications accessed via typical web access protocols.",
		RiskAssessment: "The risk rating depends on the integrity rating of the data sent across the communication link.",
		FalsePositives: "Web applications passing the authentication state via custom headers instead of cookies can " +
			"eventually be false positives. Also when the web application " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        352,
	}
}

func (*CrossSiteRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossSiteRequestForgeryRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		incomingFlows := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if !incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				continue
			}
			risks = append(risks, r.createRisk(parsedModel, technicalAsset, incomingFlow))
		}
	}
	return risks, nil
}

func (csrf CrossSiteRequestForgeryRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.WebApplication)
}

func (r *CrossSiteRequestForgeryRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink) *types.Risk {
	sourceAsset := parsedModel.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	// Already single-dimension (Integrity, matching this category's STRIDE value) by design, but
	// scoped to the comm link's own Integrity rating rather than the target asset's, since CSRF's
	// real consequence is the integrity of the data sent across this specific link -- not reused
	// via the shared computeImpact() helper, which operates on the asset's own CIA fields.
	impact := types.LowImpact
	if parsedModel.HighestCommunicationLinkIntegrity(incomingFlow) == types.MissionCritical {
		impact = types.MediumImpact
	}
	likelihood := computeLikelihood(r.likelihoodFromUsage(incomingFlow), technicalAsset)
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}

func (*CrossSiteRequestForgeryRule) likelihoodFromUsage(cl *types.CommunicationLink) types.RiskExploitationLikelihood {
	if cl.Usage == types.DevOps {
		return types.Likely
	}
	return types.VeryLikely
}
