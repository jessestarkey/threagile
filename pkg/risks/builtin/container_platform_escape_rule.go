package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ContainerPlatformEscapeRule struct{}

func NewContainerPlatformEscapeRule() *ContainerPlatformEscapeRule {
	return &ContainerPlatformEscapeRule{}
}

func (*ContainerPlatformEscapeRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "container-platform-escape",
		Title: "Container Platform Escape",
		Description: "Container platforms are especially interesting targets for attackers as they host big parts of a containerized runtime infrastructure. " +
			"When not configured and operated with security best practices in mind, attackers might exploit a vulnerability inside an container and escape towards " +
			"the platform as highly privileged users. These scenarios might give attackers capabilities to attack every other container as owning the container platform " +
			"(via container escape attacks) equals to owning every container.",
		Impact: "If this risk is unmitigated, attackers which have successfully compromised a container (via other vulnerabilities) " +
			"might be able to deeply persist in the target system by executing code in many deployed containers " +
			"and the container platform itself.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action: "Harden the container platform against escape: enforce the restricted pod security profile, block privileged " +
			"and host-namespace workloads, and apply the DISA Kubernetes STIG or CIS Kubernetes Benchmark.",
		Mitigation: "Enforce the Kubernetes Pod Security Standards restricted profile (Pod Security Admission or an equivalent " +
			"policy engine) on every workload namespace: no privileged containers, no hostPID, hostIPC, or hostNetwork, no " +
			"hostPath mounts, runAsNonRoot, allowPrivilegeEscalation false, all Linux capabilities dropped, a read-only " +
			"root filesystem, and a RuntimeDefault or stricter seccomp profile plus AppArmor or SELinux confinement. Never " +
			"mount the container runtime socket (docker.sock, containerd.sock) into a workload. Disable automatic " +
			"service-account token mounting where unused and bind service accounts to least-privilege RBAC roles with no " +
			"cluster-admin or wildcard verbs. Block pod access to the kubelet API and the cloud instance metadata endpoint " +
			"(NetworkPolicy; IMDSv2 with hop limit 1). Patch node kernels and the container runtime promptly, since many " +
			"escapes are kernel or runc bugs (for example CVE-2019-5736, CVE-2022-0185, CVE-2024-21626). Use sandboxed " +
			"runtimes (gVisor, Kata Containers) for workloads handling untrusted input, and separate workloads of " +
			"differing sensitivity onto dedicated node pools with taints and tolerations. Validate continuously with " +
			"kube-bench against the STIG or CIS benchmark, and run runtime threat detection (Falco, Defender for " +
			"Containers, GuardDuty EKS Runtime Monitoring). References: CWE-250, CWE-269; MITRE ATT&CK T1611 (Escape to " +
			"Host), T1610 (Deploy Container); NIST SP 800-190.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS or CSVS chapter applied?",
		Function:       types.Operations,
		STRIDE:         types.ElevationOfPrivilege,
		DetectionLogic: "In-scope container platforms.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Container platforms not running parts of the target architecture can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (*ContainerPlatformEscapeRule) SupportedTags() []string {
	return []string{"docker", "kubernetes", "openshift"}
}

func (r *ContainerPlatformEscapeRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]

		if r.skipAsset(technicalAsset) {
			continue
		}

		if technicalAsset.Technologies.GetAttribute(types.ContainerPlatform) {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}

func (asl ContainerPlatformEscapeRule) skipAsset(techAsset *types.TechnicalAsset) bool {
	return techAsset.OutOfScope
}

func (r *ContainerPlatformEscapeRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Container Platform Escape</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	// data breach at all container assets
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for id, techAsset := range parsedModel.TechnicalAssets {
		if techAsset.Machine == types.Container {
			dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, id)
		}
	}
	// create risk
	likelihood := computeLikelihood(types.Unlikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
