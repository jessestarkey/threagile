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
		Mitigation: "Pass the end user's identity downstream as a signed, audience-restricted token (an OAuth access token, an RFC 8693 token-exchange or on-behalf-of token, or a signed internal JWT), instead of a service-account call with no user context.\n" +
			"In this asset, validate each token's signature, issuer, audience, and expiry, and authorize each operation against the user's entitlements and object ownership, so a compromised upstream component cannot reach other users' records.\n" +
			"Never accept user identifiers from unsigned headers or request bodies.\n" +
			"Where a technical identity is unavoidable (batch jobs or DevOps flows), use a least-privilege identity per caller, and log the originating user or job for audit.",
		Check:        "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:     types.Architecture,
		STRIDE:       types.ElevationOfPrivilege,
		FindingClass: types.FindingClassWeaknessShown,
		DetectionLogic: "In-scope service-like technical assets which usually process data based on end user requests, if authenticated " +
			"(i.e. non-public), should authorize incoming requests based on the propagated end user identity when their rating is sensitive. " +
			"This is especially the case for all multi-tenant assets (there even less-sensitive rated ones). " +
			"DevOps usages are exempted from this risk.",
		RiskAssessment: "Likelihood starts at Possible. Impact starts at Low and steps on the highest of the asset's own confidentiality, integrity and availability ratings. Each step is one level: impact up for a rating of confidential/critical or above, down for internal/operational or below; likelihood also moves with the asset's attractiveness (RAA) and internet exposure.",
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

			risks = append(risks, r.createRisk(input, technicalAsset, commLink))
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

func (r *MissingIdentityPropagationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingAccess *types.CommunicationLink) *types.Risk {
	impact := computeImpact(types.LowImpact, r.Category().STRIDE, technicalAsset)
	likelihood := computeLikelihood(types.PossibleLikelihood, technicalAsset)
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
