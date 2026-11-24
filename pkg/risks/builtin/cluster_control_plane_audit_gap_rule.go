package builtin

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

// ClusterControlPlaneAuditGapRule raises a missing control-plane audit policy. The policy is one
// cluster-wide setting, and script rules can attach findings only to technical assets, so this is a
// built-in rule. It attaches the finding to the shared runtime the containers run on, which is the
// model's representation of the cluster, and falls back to a container on no shared runtime.
type ClusterControlPlaneAuditGapRule struct{}

func NewClusterControlPlaneAuditGapRule() *ClusterControlPlaneAuditGapRule {
	return &ClusterControlPlaneAuditGapRule{}
}

func (*ClusterControlPlaneAuditGapRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "cluster-control-plane-audit-gap",
		Title: "Container Orchestrator Control-Plane Audit Logging Gap",
		Description: "The cluster's audit policy is left at its default, which does not capture pod exec, port-forward, " +
			"secret access, or admission-controller decisions.",
		Impact: "If this risk remains unmitigated, post-compromise lateral movement inside the cluster produces no audit " +
			"trail for an incident responder to reconstruct.",
		ASVS:       "V7 - Error Handling and Logging",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html",
		Action: "Deploy an explicit Kubernetes audit policy capturing exec/attach/port-forward, secret access, and " +
			"admission-controller decisions at Request or RequestResponse level, forwarded to the SIEM.",
		Mitigation: "Configure the API server audit policy to capture, at minimum, RequestResponse-level logging for " +
			"pods/exec, pods/attach, pods/portforward subresources; secrets get/list/watch operations; and all admission " +
			"webhook decisions. Forward the audit log to the central SIEM with retention matching the platform's " +
			"incident-response window. References: NIST SP 800-53 AU-2 (Event Logging); NIST SP 800-53 AU-12 (Audit " +
			"Record Generation); CIS Kubernetes Benchmark (Control Plane Logging).",
		Check: "Is an explicit API server audit policy covering exec/attach/port-forward, secret access and admission " +
			"decisions deployed and forwarding to the SIEM?",
		Function:     types.Operations,
		STRIDE:       types.Repudiation,
		FindingClass: types.FindingClassControlNotEvidenced,
		DetectionLogic: "Review the API server's configured audit policy for coverage of exec/attach/port-forward, secret " +
			"access, and admission decisions, and confirm the audit log is forwarding to the SIEM.",
		RiskAssessment: "Likelihood starts at Likely and takes the highest any container on the cluster reaches. Impact " +
			"starts at Low and steps on the highest integrity rating among its containers. Each step is one level: " +
			"impact up for a rating of confidential/critical or above, down for internal/operational or below; " +
			"likelihood also moves with the asset's attractiveness (RAA) and internet exposure. High for any cluster " +
			"running the API server's default audit policy (or no audit policy) rather than one explicitly scoped to " +
			"security-relevant subresources and admission decisions.",
		FalsePositives: "Fires once per shared runtime (the cluster) that runs in-scope containers, and once for any " +
			"in-scope container that runs on no shared runtime. Model each cluster as a shared runtime so the finding " +
			"lands on it once. Dispose of a confirmed-compliant cluster through risk_tracking: log it as mitigated once " +
			"an explicit audit policy covering exec/attach/port-forward, secret access, and admission decisions is " +
			"deployed and forwarding to the SIEM.",
		CWE: 778,
	}
}

func (*ClusterControlPlaneAuditGapRule) SupportedTags() []string {
	return []string{}
}

func (r *ClusterControlPlaneAuditGapRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	onRuntime := make(map[string]bool)

	runtimeIDs := make([]string, 0, len(input.SharedRuntimes))
	for id := range input.SharedRuntimes {
		runtimeIDs = append(runtimeIDs, id)
	}
	sort.Strings(runtimeIDs)
	for _, id := range runtimeIDs {
		runtime := input.SharedRuntimes[id]
		containers := make([]*types.TechnicalAsset, 0)
		for _, assetID := range runtime.TechnicalAssetsRunning {
			asset := input.TechnicalAssets[assetID]
			if asset == nil || asset.OutOfScope || asset.Machine != types.Container {
				continue
			}
			containers = append(containers, asset)
			onRuntime[asset.Id] = true
		}
		if len(containers) > 0 {
			risks = append(risks, r.createRisk(runtime.Id, runtime.Title, containers, true))
		}
	}

	assetIDs := make([]string, 0, len(input.TechnicalAssets))
	for id := range input.TechnicalAssets {
		assetIDs = append(assetIDs, id)
	}
	sort.Strings(assetIDs)
	for _, id := range assetIDs {
		asset := input.TechnicalAssets[id]
		if asset.OutOfScope || asset.Machine != types.Container || onRuntime[asset.Id] {
			continue
		}
		risks = append(risks, r.createRisk(asset.Id, asset.Title, []*types.TechnicalAsset{asset}, false))
	}
	return risks, nil
}

// createRisk raises one finding for a cluster (a shared runtime) or a lone container. Likelihood is
// the highest any of its containers reaches, since an attacker lands on the most exposed one, and
// impact follows the highest integrity among them, since a missing audit trail lets tampering go
// unreconstructed.
func (r *ClusterControlPlaneAuditGapRule) createRisk(id, title string, containers []*types.TechnicalAsset, isRuntime bool) *types.Risk {
	likelihood := types.Unlikely
	rank := 0
	ids := make([]string, 0, len(containers))
	for _, container := range containers {
		likelihood = max(likelihood, computeLikelihood(types.Likely, container))
		rank = max(rank, rankForStride(r.Category().STRIDE, container.Confidentiality, container.Integrity, container.Availability))
		ids = append(ids, container.Id)
	}
	sort.Strings(ids)
	impact := types.AdjustImpactForRank(types.LowImpact, rank)
	risk := &types.Risk{
		CategoryId:                  r.Category().ID,
		Severity:                    types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:      likelihood,
		ExploitationImpact:          impact,
		Title:                       "<b>Container Orchestrator Control-Plane Audit Logging Gap</b> risk at <b>" + title + "</b>",
		DataBreachProbability:       types.Possible,
		DataBreachTechnicalAssetIDs: ids,
		SyntheticId:                 r.Category().ID + "@" + id,
	}
	if isRuntime {
		// A shared runtime and a technical asset may share an id; keep their findings apart.
		risk.SyntheticId = r.Category().ID + "@shared-runtime:" + id
		risk.MostRelevantSharedRuntimeId = id
	} else {
		risk.MostRelevantTechnicalAssetId = id
	}
	return risk
}
