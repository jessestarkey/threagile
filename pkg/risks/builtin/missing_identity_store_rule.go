package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingIdentityStoreRule struct{}

func NewMissingIdentityStoreRule() *MissingIdentityStoreRule {
	return &MissingIdentityStoreRule{}
}

func (*MissingIdentityStoreRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-identity-store",
		Title: "Missing Identity Store",
		Description: "The modeled architecture does not contain an identity store, which might be the risk of a model missing " +
			"critical assets (and thus not seeing their risks).",
		Impact: "If this risk is unmitigated, attackers might be able to exploit risks unseen in this threat model in the identity provider/store " +
			"that is currently missing in the model.",
		ASVS:       "V2 - Authentication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
		Action: "Add the identity provider and identity store that authenticate this system's users to the threat model, with " +
			"their data flows to every asset that authorizes by end-user identity.",
		Mitigation: "Model the identity provider (for example Entra ID, Keycloak, Okta) and its identity store (directory or user database) as technical assets, as out-of-scope assets if an enterprise identity team operates them, with the authentication and token-validation communication links to every asset that authorizes requests by end-user identity. Without them, risks to the component that issues every credential this system trusts (identity provider isolation, missing MFA, credential storage, federation trust tampering) cannot be evaluated.\n" +
			"Record whether the identity service is inherited from an enterprise authorization package or operated by this system, since that determines which controls this system must implement itself.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Spoofing,
		FindingClass:   types.FindingClassControlNotEvidenced,
		DetectionLogic: "Models with authenticated data-flows authorized via end user identity missing an in-scope identity store.",
		RiskAssessment: "The risk rating depends on the sensitivity of the end user-identity authorized technical assets and " +
			"their data assets processed.",
		FalsePositives: "Models only offering data/services without any real authentication need " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        287,
	}
}

func (*MissingIdentityStoreRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingIdentityStoreRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	for _, technicalAsset := range input.TechnicalAssets {
		if r.skipAsset(technicalAsset) {
			// everything fine, no risk, as we have an in-scope identity store in the model
			return []*types.Risk{}, nil
		}
	}
	// now check if we have end user identity authorized communication links, then it's a risk
	for _, technicalAsset := range input.TechnicalAssets {
		for _, commLink := range technicalAsset.CommunicationLinks {
			if commLink.Authorization == types.EndUserIdentityPropagation {
				// A gap in the whole model, so the finding belongs to the system and stays flat at
				// Low, exempt from the CIA step (docs/risk-methodology.md).
				return []*types.Risk{wholeModelRisk(r.Category().ID, "<b>Missing Identity Store</b> in the threat model",
					types.LowImpact)}, nil
			}
		}
	}
	return []*types.Risk{}, nil
}

func (r *MissingIdentityStoreRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return !technicalAsset.OutOfScope && technicalAsset.Technologies.GetAttribute(types.IsIdentityStore)
}
