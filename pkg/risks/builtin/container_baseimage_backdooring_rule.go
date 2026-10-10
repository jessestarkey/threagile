package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ContainerBaseImageBackdooringRule struct{}

func NewContainerBaseImageBackdooringRule() *ContainerBaseImageBackdooringRule {
	return &ContainerBaseImageBackdooringRule{}
}

func (*ContainerBaseImageBackdooringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "container-baseimage-backdooring",
		Title: "Container Base Image Backdooring",
		Description: "When a technical asset is built using container technologies, Base Image Backdooring risks might arise where " +
			"base images and other layers used contain vulnerable components or backdoors." +
			"<br><br>See for example: <a href=\"https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/\">https://techcrunch.com/2018/06/15/tainted-crypto-mining-containers-pulled-from-docker-hub/</a>",
		Impact:     "If this risk is unmitigated, attackers might be able to deeply persist in the target system by executing code in deployed containers.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action: "Build containers only from approved, digest-pinned, signature-verified base images mirrored into a hardened " +
			"internal registry, and scan every image layer before deployment.",
		Mitigation: "Source base images only from a vetted hardened catalog (for DoD workloads, Iron Bank hardened images; " +
			"otherwise vendor-signed minimal images such as distroless) mirrored into an internal registry, and block " +
			"pulls from public registries at the network and admission-control layer. Reference base images by immutable " +
			"sha256 digest in every Dockerfile, never by a mutable tag such as latest. Verify the base image signature " +
			"(cosign, Notation) during the build, and verify the final image signature at deployment with an admission " +
			"controller (Kyverno, OPA Gatekeeper, or Sigstore policy-controller) that rejects unsigned or unapproved " +
			"images. Scan every layer for known vulnerabilities and embedded malware in CI (Trivy, Grype, Anchore) and " +
			"fail the build on critical findings, then rescan images already in the registry on a schedule, since new CVEs " +
			"are published after build time. Generate and retain an SBOM (SPDX or CycloneDX) per image. Keep runtime " +
			"images minimal (no shell, package manager, or compiler) and rebuild on a fixed cadence to pick up patched " +
			"base layers. References: CWE-506, CWE-1395; MITRE ATT&CK T1525 (Implant Internal Image), T1195.002; NIST SP " +
			"800-190; DoD Container Image Creation and Deployment Guide.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS/CSVS applied?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope technical assets running as containers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets.",
		FalsePositives: "Fully trusted (i.e. reviewed and cryptographically signed or similar) base images of containers can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        912,
	}
}

func (*ContainerBaseImageBackdooringRule) SupportedTags() []string {
	return []string{}
}

func (r *ContainerBaseImageBackdooringRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Machine == types.Container {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}

func (r *ContainerBaseImageBackdooringRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Container Base Image Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact intentionally stays keyed off all three CIA dimensions rather than narrowing to
	// just Integrity (this category's own STRIDE value): a backdoored base image grants code
	// execution inside the container, which can read, modify, or deny whatever that container
	// handles regardless of which single dimension is highest-rated.
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood := computeLikelihood(types.Unlikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
