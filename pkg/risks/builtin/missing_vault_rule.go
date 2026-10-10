package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingVaultRule struct{}

func NewMissingVaultRule() *MissingVaultRule {
	return &MissingVaultRule{}
}

func (*MissingVaultRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-vault",
		Title: "Missing Vault (Secret Storage)",
		Description: "In order to avoid the risk of secret leakage via config files (when attacked through vulnerabilities being able to " +
			"read files like Path-Traversal and others), it is best practice to use a separate hardened process with proper authentication, " +
			"authorization, and audit logging to access config secrets (like credentials, private keys, client certificates, etc.). " +
			"This component is usually some kind of Vault.",
		Impact: "If this risk is unmitigated, attackers might be able to easier steal config secrets (like credentials, private keys, client certificates, etc.) once " +
			"a vulnerability to access files is present and exploited.",
		ASVS:       "V6 - Stored Cryptography Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action: "Move every credential, key, and certificate out of configuration files, images, and environment variables " +
			"into a dedicated secrets vault accessed through workload identity.",
		Mitigation: "Deploy a dedicated secrets management service (Azure Key Vault, AWS Secrets Manager with KMS, HashiCorp " +
			"Vault), HSM-backed where required (FIPS 140-2/140-3 Level 2 or higher for DoD), and migrate every database " +
			"password, API key, client secret, TLS private key, and signing key out of configuration files, container " +
			"images, Kubernetes manifests, and plain environment variables. Have workloads authenticate to the vault with " +
			"workload identity (managed identity, IAM roles for service accounts, Kubernetes auth) rather than a bootstrap " +
			"secret, and retrieve secrets at runtime or through a CSI secrets-store driver. Grant each workload read " +
			"access to its own secrets only, enable soft-delete and purge protection, and send all vault access logs to " +
			"the SIEM. Prefer dynamic, short-lived credentials (per-lease database credentials, short-lived certificates) " +
			"and automate rotation for any static secret that remains. References: CWE-798, CWE-522, CWE-312; MITRE ATT&CK " +
			"T1552.001 (Credentials In Files), T1552.004 (Private Keys); NIST SP 800-53 IA-5, SC-12, SC-28; NIST SP 800-57.",
		Check:          "GetAttribute a Vault (Secret Storage) in place?",
		Function:       types.Architecture,
		STRIDE:         types.InformationDisclosure,
		DetectionLogic: "Models without a Vault (Secret Storage).",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Models where no technical assets have any kind of sensitive config data to protect " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        522,
	}
}

func (*MissingVaultRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingVaultRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	hasVault := false
	var mostRelevantAsset *types.TechnicalAsset
	impact := types.LowImpact
	for _, id := range input.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with the highest sensitivity as example asset
		techAsset := input.TechnicalAssets[id]
		if techAsset.Technologies.GetAttribute(types.Vault) {
			hasVault = true
			break
		}
		if input.HighestProcessedConfidentiality(techAsset) >= types.Confidential ||
			input.HighestProcessedIntegrity(techAsset) >= types.Critical ||
			input.HighestProcessedAvailability(techAsset) >= types.Critical {
			impact = types.MediumImpact
		}
		if techAsset.Confidentiality >= types.Confidential ||
			techAsset.Integrity >= types.Critical ||
			techAsset.Availability >= types.Critical {
			impact = types.MediumImpact
		}
		// just for referencing the most interesting asset
		if mostRelevantAsset == nil || techAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
			mostRelevantAsset = techAsset
		}
	}
	if !hasVault {
		risks = append(risks, r.createRisk(mostRelevantAsset, impact))
	}
	return risks, nil
}

func (r *MissingVaultRule) createRisk(technicalAsset *types.TechnicalAsset, impact types.RiskExploitationImpact) *types.Risk {
	title := "<b>Missing Vault (Secret Storage)</b> in the threat model"
	id := "no-components"
	if technicalAsset != nil {
		title += " (referencing asset <b>" + technicalAsset.Title + "</b> as an example)"
		id = technicalAsset.Id
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + id
	return risk
}
