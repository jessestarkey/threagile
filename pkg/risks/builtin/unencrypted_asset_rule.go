package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type UnencryptedAssetRule struct{}

func NewUnencryptedAssetRule() *UnencryptedAssetRule {
	return &UnencryptedAssetRule{}
}

func (*UnencryptedAssetRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unencrypted-asset",
		Title: "Unencrypted Technical Assets",
		Description: "Due to the confidentiality rating of the technical asset itself and/or the stored data assets " +
			"this technical asset must be encrypted. The risk rating depends on the sensitivity technical asset itself and of the data assets stored.",
		Impact:     "If this risk is unmitigated, attackers might be able to access unencrypted data when successfully compromising sensitive components.",
		ASVS:       "V6 - Stored Cryptography Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action: "Enable encryption at rest for this asset and all of its backups and snapshots using FIPS 140-validated " +
			"cryptography, with customer-managed keys held in a separate key vault for sensitive data.",
		Mitigation: "Encrypt every volume, database, bucket, backup, and snapshot of this asset (Azure Storage Service Encryption and TDE, AWS EBS, S3, and RDS encryption, or LUKS or BitLocker on self-managed hosts) with FIPS 140-2 or 140-3 validated modules.\n" +
			"For CUI and more sensitive data, restrict the customer-managed keys to the storage service's identity, rotate them on a defined schedule, and log key access.\n" +
			"Where the threat includes privileged insiders or a running-host compromise, add field-level encryption (SQL Always Encrypted or envelope encryption) for the most sensitive fields, since volume encryption protects only against offline media access.\n" +
			"Encrypt temporary files, caches, swap, and logs that may hold sensitive data, and enforce encryption through policy (Azure Policy or AWS Config) so unencrypted resources cannot be created.",
		Check:        "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:     types.Operations,
		STRIDE:       types.InformationDisclosure,
		FindingClass: types.FindingClassWeaknessShown,
		DetectionLogic: "In-scope unencrypted technical assets (excluding " + types.ReverseProxy +
			", " + types.LoadBalancer + ", " + types.WAF + ", " + types.IDS +
			", " + types.IPS + " and embedded components like " + types.Library + ") " +
			"storing data assets rated at least as " + types.Confidential.String() + " or " + types.Critical.String() + ". " +
			"For technical assets storing data assets rated as " + types.StrictlyConfidential.String() + " or " + types.MissionCritical.String() + " the " +
			"encryption must be of type " + types.DataWithEndUserIndividualKey.String() + ".",
		// NOTE: the risk assessment does not only consider the CIs of the *stored* data-assets
		RiskAssessment:             "Likelihood starts at Unlikely. Impact starts at Low and steps on the confidentiality of the data the asset stores. Each step is one level: impact up for a rating of confidential/critical or above, down for internal/operational or below; likelihood also moves with the asset's attractiveness (RAA) and internet exposure.",
		FalsePositives:             "When all sensitive data stored within the asset is already fully encrypted on document or data level.",
		ModelFailurePossibleReason: false,
		CWE:                        311,
	}
}

func (*UnencryptedAssetRule) SupportedTags() []string {
	return []string{}
}

// check for technical assets that should be encrypted due to their confidentiality

func (r *UnencryptedAssetRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		highestStoredConfidentiality := input.HighestStoredConfidentiality(technicalAsset)
		highestStoredIntegrity := input.HighestStoredIntegrity(technicalAsset)
		if technicalAsset.OutOfScope || isEncryptionWaiver(technicalAsset) {
			continue
		}
		if len(technicalAsset.DataAssetsStored) == 0 {
			continue
		}
		if highestStoredConfidentiality < types.Confidential || highestStoredIntegrity < types.Critical {
			continue
		}

		verySensitive := highestStoredConfidentiality == types.StrictlyConfidential || highestStoredIntegrity == types.MissionCritical
		requiresEndUserKey := verySensitive && technicalAsset.Technologies.GetAttribute(types.IsUsuallyStoringEndUserData)
		// Encryption at rest protects what the asset stores, so the CIA step reads the stored data.
		storedImpact := impactForRatings(types.LowImpact, r.Category().STRIDE, highestStoredConfidentiality,
			highestStoredIntegrity, input.HighestStoredAvailability(technicalAsset))
		if technicalAsset.Encryption == types.NoneEncryption {
			risks = append(risks, r.createRisk(technicalAsset, storedImpact, requiresEndUserKey))
			continue
		}
		if requiresEndUserKey && technicalAsset.Encryption != types.DataWithEndUserIndividualKey {
			risks = append(risks, r.createRisk(technicalAsset, storedImpact, requiresEndUserKey))
			continue
		}
	}
	return risks, nil
}

// Simple routing assets like 'Reverse Proxy' or 'Load Balancer' usually don't have their own storage and thus have no
// encryption requirement for the asset itself (though for the communication, but that's a different rule)

func isEncryptionWaiver(asset *types.TechnicalAsset) bool {
	return asset.Technologies.GetAttribute(types.IsNoStorageAtRest) || asset.Technologies.GetAttribute(types.IsEmbeddedComponent)
}

func (r *UnencryptedAssetRule) createRisk(technicalAsset *types.TechnicalAsset, impact types.RiskExploitationImpact, requiresEndUserKey bool) *types.Risk {
	title := "<b>Unencrypted Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	if requiresEndUserKey {
		title += " missing end user individual encryption with " + types.DataWithEndUserIndividualKey.String()
	}
	// Impact: baseline plus the CIA step on the dimension the STRIDE category threatens
	// (confidentiality), for the data the asset stores.
	likelihood := computeLikelihood(types.Unlikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
