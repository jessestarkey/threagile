package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingVaultIsolationRule struct{}

func NewMissingVaultIsolationRule() *MissingVaultIsolationRule {
	return &MissingVaultIsolationRule{}
}

func (*MissingVaultIsolationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-vault-isolation",
		Title: "Missing Vault Isolation",
		Description: "Highly sensitive vault assets and their data stores should be isolated from other assets " +
			"by their own network segmentation trust-boundary (" + types.ExecutionEnvironment.String() + " boundaries do not count as network isolation).",
		Impact: "If this risk is unmitigated, attackers successfully attacking other components of the system might have an easy path towards " +
			"highly sensitive vault assets and their data stores, as they are not separated by network segmentation.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action: "Isolate the secrets vault and its storage backend in a dedicated network segment reachable only through " +
			"private endpoints by the workloads that need it.",
		Mitigation: "Disable public network access on the vault and expose it only through private endpoints or VPC endpoints in a " +
			"dedicated subnet with a default-deny network policy admitting only the specific workload subnets and " +
			"management paths that need it. Do not co-host a self-managed vault (for example HashiCorp Vault) or its " +
			"storage backend (Raft, Consul, a database) on the same servers, node pool, or database instance as " +
			"application workloads. Restrict vault administration to privileged access workstations with just-in-time " +
			"elevation, separate vault administrator roles from secret-consumer roles, and require MFA for all human " +
			"access. Alert on vault policy changes, new access grants, bulk secret reads, and access from unexpected " +
			"network sources. References: CWE-653; MITRE ATT&CK T1555 (Credentials from Password Stores), T1552 (Unsecured " +
			"Credentials); NIST SP 800-53 SC-7, SC-12, AC-6.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Operations,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope vault assets " +
			"when surrounded by other (not vault-related) assets (without a network trust-boundary in-between). " +
			"This risk is especially prevalent when other non-vault related assets are within the same execution environment (i.e. same database or same application server).",
		RiskAssessment: "Default is " + types.MediumImpact.String() + " impact. The impact is increased to " + types.HighImpact.String() + " when the asset missing the " +
			"trust-boundary protection is rated as " + types.StrictlyConfidential.String() + " or " + types.MissionCritical.String() + ".",
		FalsePositives: "When all assets within the network segmentation trust-boundary are hardened and protected to the same extend as if all were " +
			"vaults with data of highest sensitivity.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (*MissingVaultIsolationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingVaultIsolationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.Vault) {
			continue
		}
		moreImpact := technicalAsset.Confidentiality == types.StrictlyConfidential ||
			technicalAsset.Integrity == types.MissionCritical ||
			technicalAsset.Availability == types.MissionCritical
		sameExecutionEnv := false
		createRiskEntry := false
		// now check for any other same-network assets of non-vault-related types
		for sparringAssetCandidateId := range input.TechnicalAssets { // so inner loop again over all assets
			if technicalAsset.Id == sparringAssetCandidateId {
				continue
			}
			sparringAssetCandidate := input.TechnicalAssets[sparringAssetCandidateId]
			if sparringAssetCandidate.Technologies.GetAttribute(types.Vault) || isVaultStorage(input, technicalAsset, sparringAssetCandidate) {
				continue
			}

			if isSameExecutionEnvironment(input, technicalAsset, sparringAssetCandidateId) {
				createRiskEntry = true
				sameExecutionEnv = true
			} else if isSameTrustBoundaryNetworkOnly(input, technicalAsset, sparringAssetCandidateId) {
				createRiskEntry = true
			}
		}
		if createRiskEntry {
			risks = append(risks, r.createRisk(technicalAsset, moreImpact, sameExecutionEnv))
		}
	}
	return risks, nil
}

func isVaultStorage(parsedModel *types.Model, vault *types.TechnicalAsset, storage *types.TechnicalAsset) bool {
	return storage.Type == types.Datastore && parsedModel.HasDirectConnection(vault, storage.Id)
}

func (r *MissingVaultIsolationRule) createRisk(techAsset *types.TechnicalAsset, moreImpact bool, sameExecutionEnv bool) *types.Risk {
	impact := types.MediumImpact
	baselineLikelihood := types.Unlikely
	others := "<b>in the same network segment</b>"
	if moreImpact {
		impact = types.HighImpact
	}
	if sameExecutionEnv {
		baselineLikelihood = types.Likely
		others = "<b>in the same execution environment</b>"
	}
	likelihood := computeLikelihood(baselineLikelihood, techAsset)
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Missing Vault Isolation</b> to further encapsulate and protect vault-related asset <b>" + techAsset.Title + "</b> against unrelated " +
			"lower protected assets " + others + ", which might be easier to compromise by attackers",
		MostRelevantTechnicalAssetId: techAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{techAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + techAsset.Id
	return risk
}
