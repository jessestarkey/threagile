package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingIdentityPropagationRule struct{}

func NewMissingIdentityPropagationRule() *MissingIdentityPropagationRule {
	return &MissingIdentityPropagationRule{}
}

func (*MissingIdentityPropagationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-identity-propagation",
		Title: "Missing Identity Propagation",
		Description: "Technical assets (especially multi-tenant systems), which usually process data for end users should " +
			"authorize every request based on the identity of the end user when the data flow is authenticated (i.e. non-public). " +
			"For DevOps usages at least a technical-user authorization is required.",
		Impact: "If this risk is unmitigated, attackers might be able to access or modify foreign data after a successful compromise of a component within " +
			"the system due to missing resource-based authorization checks.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action: "Propagate the end user's verified identity to this backend asset in a signed token, and enforce object- and " +
			"function-level authorization against that identity on every request.",
		Mitigation: "Pass the end user's identity downstream as a signed, audience-restricted token (an OAuth 2.0 access token, an " +
			"RFC 8693 token-exchange or on-behalf-of token, or a signed internal JWT) instead of a trusted service-account " +
			"call that carries no user context. In this asset, validate the token's signature, issuer, audience, and " +
			"expiry on every request, and authorize each operation against the user's entitlements and ownership of the " +
			"requested object, so a compromised upstream component cannot read or change other users' records by calling " +
			"this service directly. Never accept user identifiers from unsigned headers or request bodies. Where a " +
			"technical identity is unavoidable (batch jobs, DevOps flows), use a dedicated least-privilege service " +
			"identity per caller, scoped to only the operations that caller needs, and log the originating user or job " +
			"identifier for audit. References: CWE-639, CWE-285; OWASP API Security Top 10:2023 API1 (Broken Object Level " +
			"Authorization), API5 (Broken Function Level Authorization); OWASP Top 10:2025 A01 (Broken Access Control); " +
			"NIST SP 800-53 AC-3, AC-6; NIST SP 800-207.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope service-like technical assets which usually process data based on end user requests, if authenticated " +
			"(i.e. non-public), should authorize incoming requests based on the propagated end user identity when their rating is sensitive. " +
			"This is especially the case for all multi-tenant assets (there even less-sensitive rated ones). " +
			"DevOps usages are exempted from this risk.",
		RiskAssessment: "The risk rating (medium or high) " +
			"depends on the confidentiality, integrity, and availability rating of the technical asset.",
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        284,
	}
}

func (*MissingIdentityPropagationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingIdentityPropagationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}

		// check each incoming authenticated data flow
		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, commLink := range commLinks {
			caller := input.TechnicalAssets[commLink.SourceId]
			if r.skipCommunicationLinkAsset(caller, commLink) {
				continue
			}

			highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
				technicalAsset.Integrity == types.MissionCritical ||
				technicalAsset.Availability == types.MissionCritical
			risks = append(risks, r.createRisk(input, technicalAsset, commLink, highRisk))
		}
	}
	return risks, nil
}

func (r *MissingIdentityPropagationRule) skipCommunicationLinkAsset(caller *types.TechnicalAsset, commLink *types.CommunicationLink) bool {
	if !caller.Technologies.GetAttribute(types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets) || caller.Type == types.Datastore {
		return true
	}
	if commLink.Authentication == types.NoneAuthentication || commLink.Authorization == types.EndUserIdentityPropagation {
		return true
	}
	if commLink.Usage == types.DevOps && commLink.Authorization != types.NoneAuthorization {
		return true
	}
	return false
}

func (r *MissingIdentityPropagationRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	if technicalAsset.OutOfScope {
		return true
	}
	if !technicalAsset.Technologies.GetAttribute(types.IsUsuallyProcessingEndUserRequests) {
		return true
	}
	if technicalAsset.MultiTenant && technicalAsset.Confidentiality < types.Restricted && technicalAsset.Integrity < types.Important && technicalAsset.Availability < types.Important {
		return true
	}
	if !technicalAsset.MultiTenant && technicalAsset.Confidentiality < types.Confidential && technicalAsset.Integrity < types.Critical && technicalAsset.Availability < types.Critical {
		return true
	}
	return false
}

func (r *MissingIdentityPropagationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingAccess *types.CommunicationLink, moreRisky bool) *types.Risk {
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	likelihood := computeLikelihood(types.Unlikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing End User Identity Propagation</b> over communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + input.TechnicalAssets[incomingAccess.SourceId].Title + "</b> " +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + incomingAccess.Id + "@" + input.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
