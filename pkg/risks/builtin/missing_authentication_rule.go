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
		Mitigation: "Authenticate every interface of this asset rather than relying on network location. For human users, " +
			"integrate with the enterprise identity provider over OIDC or SAML using DoD CAC/PIV or another " +
			"phishing-resistant authenticator. For service-to-service calls, use mutual TLS with certificates from an " +
			"internal CA or service mesh, or short-lived workload identity tokens (managed identity, IAM roles for service " +
			"accounts, SPIFFE/SPIRE) validated on every request for signature, issuer, audience, and expiry; avoid " +
			"long-lived shared API keys. Enforce authentication with a default-deny filter at the framework or gateway so " +
			"new endpoints are protected unless explicitly marked public, and review every public exception. Disable or " +
			"authenticate management, metrics, and debug endpoints that ship unauthenticated by default (Spring Boot " +
			"Actuator, Elasticsearch, Redis, etcd, database admin consoles). References: CWE-306, CWE-287; MITRE ATT&CK " +
			"T1190 (Exploit Public-Facing Application); OWASP Top 10:2025 A07 (Authentication Failures); OWASP API " +
			"Security Top 10:2023 API2 (Broken Authentication); NIST SP 800-53 IA-2, IA-9.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope technical assets (except " + types.LoadBalancer + ", " + types.ReverseProxy + ", " + types.ServiceRegistry + ", " + types.WAF + ", " + types.IDS + ", and " + types.IPS + " and in-process calls) should authenticate incoming requests when the asset processes " +
			"sensitive data. This is especially the case for all multi-tenant assets (there even non-sensitive ones).",
		RiskAssessment: "The risk rating (medium or high) " +
			"depends on the sensitivity of the data sent across the communication link. Monitoring callers are exempted from this risk.",
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

// Already effectively keyed off the max of multiple dimensions (this category's STRIDE value,
// ElevationOfPrivilege, is exactly the case computeImpact() itself falls back to max(C,I,A) for),
// scoped to the comm link's own ratings rather than the target asset's -- not reused via the
// shared computeImpact() helper, which operates on the asset's own CIA fields, not a link's.
func (r *MissingAuthenticationRule) calculateImpact(commLink *types.CommunicationLink, input *types.Model) types.RiskExploitationImpact {
	if input.HighestCommunicationLinkConfidentiality(commLink) == types.StrictlyConfidential || input.HighestCommunicationLinkIntegrity(commLink) == types.MissionCritical {
		return types.HighImpact
	}
	if input.HighestCommunicationLinkConfidentiality(commLink) <= types.Internal && input.HighestCommunicationLinkIntegrity(commLink) == types.Operational {
		return types.LowImpact
	}
	return types.MediumImpact
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
