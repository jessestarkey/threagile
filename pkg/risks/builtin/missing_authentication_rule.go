package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingAuthenticationRule struct{}

func NewMissingAuthenticationRule() *MissingAuthenticationRule {
	return &MissingAuthenticationRule{}
}

func (*MissingAuthenticationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "missing-authentication",
		Title:       "Missing Authentication",
		Description: "Technical assets (especially multi-tenant systems) should authenticate incoming requests when the asset processes sensitive data. ",
		Impact:      "If this risk is unmitigated, attackers might be able to access or modify sensitive data in an unauthenticated way.",
		ASVS:        "V2 - Authentication Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action: "Require every request to this asset to carry a verified identity: enterprise identity provider authentication " +
			"for users, and mutual TLS or short-lived workload identity tokens for services.",
		Mitigation: "Authenticate every interface of this asset rather than relying on network location.\n" +
			"For users, integrate with the enterprise identity provider over OIDC or SAML, with DoD CAC/PIV or another phishing-resistant authenticator.\n" +
			"For services, use mutual TLS or short-lived workload identity tokens (such as managed identities or SPIFFE), validated on every request for signature, issuer, audience, and expiry, rather than long-lived shared API keys.\n" +
			"Enforce authentication with a default-deny filter at the framework or gateway, so new endpoints are protected unless explicitly marked public, and review every public exception.\n" +
			"Disable or authenticate management, metrics, and debug endpoints that ship unauthenticated (such as Spring Boot Actuator or database admin consoles).",
		Check:        "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:     types.Architecture,
		STRIDE:       types.ElevationOfPrivilege,
		FindingClass: types.FindingClassWeaknessShown,
		DetectionLogic: "In-scope technical assets (except " + types.LoadBalancer + ", " + types.ReverseProxy + ", " + types.ServiceRegistry + ", " + types.WAF + ", " + types.IDS + ", and " + types.IPS + " and in-process calls) should authenticate incoming requests when the asset processes " +
			"sensitive data. This is especially the case for all multi-tenant assets (there even non-sensitive ones).",
		RiskAssessment: "Likelihood starts at Likely. Impact starts at Medium and steps on the highest rating of the data on the unauthenticated link, or of the target asset when the link carries no data. Monitoring callers are exempted. Each step is one level: impact up for a rating of confidential/critical or above, down for internal/operational or below; likelihood also moves with the asset's attractiveness (RAA) and internet exposure.",
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        306,
	}
}

func (*MissingAuthenticationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingAuthenticationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technologies.GetAttribute(types.NoAuthenticationRequired) {
			continue
		}

		if input.HighestProcessedConfidentiality(technicalAsset) < types.Confidential &&
			input.HighestProcessedIntegrity(technicalAsset) < types.Critical &&
			input.HighestProcessedAvailability(technicalAsset) < types.Critical &&
			!technicalAsset.MultiTenant {
			continue
		}

		// check each incoming data flow
		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, commLink := range commLinks {
			caller := input.TechnicalAssets[commLink.SourceId]
			if caller.Technologies.GetAttribute(types.IsUnprotectedCommunicationsTolerated) || caller.Type == types.Datastore {
				continue
			}
			impact := r.calculateImpact(commLink, input)
			if commLink.Authentication == types.NoneAuthentication && !commLink.Protocol.IsProcessLocal() {
				likelihood := computeLikelihood(types.Likely, technicalAsset)
				risks = append(risks, r.createRisk(input, technicalAsset, commLink, commLink, "", impact, likelihood, false, r.Category()))
			}
		}
	}
	return risks, nil
}

// The highest of C, I, and A (this category is elevation of privilege), on the link's data rather
// than the target asset's ratings, so computeImpact() does not fit here.
func (r *MissingAuthenticationRule) calculateImpact(commLink *types.CommunicationLink, input *types.Model) types.RiskExploitationImpact {
	rank := linkRank(input, r.Category().STRIDE, commLink)
	if len(commLink.DataAssetsSent) == 0 && len(commLink.DataAssetsReceived) == 0 {
		// No data modeled on the link: the unauthenticated caller still reaches the target, so
		// rate on what the target holds rather than on an empty link (rank 0).
		rank = processedRank(input, r.Category().STRIDE, input.TechnicalAssets[commLink.TargetId])
	}
	return types.AdjustImpactForRank(types.MediumImpact, rank)
}

func (r *MissingAuthenticationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingAccess, incomingAccessOrigin *types.CommunicationLink, hopBetween string,
	impact types.RiskExploitationImpact, likelihood types.RiskExploitationLikelihood, twoFactor bool, category *types.RiskCategory) *types.Risk {
	factorString := ""
	if twoFactor {
		factorString = "Two-Factor "
	}
	if len(hopBetween) > 0 {
		hopBetween = "forwarded via <b>" + hopBetween + "</b> "
	}
	risk := &types.Risk{
		CategoryId:             category.ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing " + factorString + "Authentication</b> covering communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + input.TechnicalAssets[incomingAccessOrigin.SourceId].Title + "</b> " + hopBetween +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + incomingAccess.Id + "@" + input.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
