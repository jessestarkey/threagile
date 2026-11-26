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
		Mitigation: "Deploy a dedicated secrets service (Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault), HSM-backed where required (FIPS 140 Level 2 or higher for DoD), and migrate every password, API key, client secret, and private key into it.\n" +
			"Have workloads authenticate to the vault with workload identity rather than a bootstrap secret, and retrieve secrets at runtime or through a CSI secrets-store driver.\n" +
			"Grant each workload read access to its own secrets only, enable soft-delete and purge protection, and send vault access logs to the SIEM.\n" +
			"Prefer dynamic, short-lived credentials, and automate rotation for any static secret that remains.",
		Check:          "GetAttribute a Vault (Secret Storage) in place?",
		Function:       types.Architecture,
		STRIDE:         types.InformationDisclosure,
		FindingClass:   types.FindingClassControlNotEvidenced,
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
	highestRank := 0
	for _, id := range input.SortedTechnicalAssetIDs() {
		techAsset := input.TechnicalAssets[id]
		if techAsset.Technologies.GetAttribute(types.Vault) {
			return []*types.Risk{}, nil
		}
		highestRank = max(highestRank, processedRank(input, r.Category().STRIDE, techAsset))
	}
	// A gap in the whole model, so the finding belongs to the system rather than to an example
	// asset, and its likelihood stays flat. Impact takes the CIA step for the most sensitive data
	// that some component must then keep its secrets beside.
	return []*types.Risk{wholeModelRisk(r.Category().ID, "<b>Missing Vault (Secret Storage)</b> in the threat model",
		types.AdjustImpactForRank(types.LowImpact, highestRank))}, nil
}
