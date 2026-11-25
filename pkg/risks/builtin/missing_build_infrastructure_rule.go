package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingBuildInfrastructureRule struct{}

func NewMissingBuildInfrastructureRule() *MissingBuildInfrastructureRule {
	return &MissingBuildInfrastructureRule{}
}

func (*MissingBuildInfrastructureRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-build-infrastructure",
		Title: "Missing Build Infrastructure",
		Description: "The modeled architecture does not contain a build infrastructure (devops-client, sourcecode-repo, build-pipeline, etc.), " +
			"which might be the risk of a model missing critical assets (and thus not seeing their risks). " +
			"If the architecture contains custom-developed parts, the pipeline where code gets developed " +
			"and built needs to be part of the model.",
		Impact: "If this risk is unmitigated, attackers might be able to exploit risks unseen in this threat model due to " +
			"critical build infrastructure components missing in the model.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action: "Add the developer endpoints, source repository, build pipeline, and artifact registry that produce this " +
			"system's custom code to the threat model, with their data flows to the deployment targets.",
		Mitigation: "Model the delivery path for every custom component, namely developer workstations, the source repository, the CI/CD pipeline and its runners, the artifact registry, and their links to the deployment targets, with real trust boundaries and CIA ratings.\n" +
			"With these assets in the model, the supply-chain rules (such as code backdooring and unchecked deployment) can evaluate them. Without them, the most direct path to compromising production is invisible to the analysis.\n" +
			"If a shared enterprise team owns the build platform, model it as out of scope so its data flows still appear, and cite that platform's authorization package.",
		Check:        "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:     types.Architecture,
		STRIDE:       types.Tampering,
		FindingClass: types.FindingClassControlNotEvidenced,
		DetectionLogic: "Models with in-scope custom-developed parts missing in-scope development (code creation) and build infrastructure " +
			"components (devops-client, sourcecode-repo, build-pipeline, etc.).",
		RiskAssessment: "The risk rating depends on the highest sensitivity of the in-scope assets running custom-developed parts.",
		FalsePositives: "Models not having any custom-developed parts " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: true,
		CWE:                        1127,
	}
}

func (*MissingBuildInfrastructureRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingBuildInfrastructureRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	hasCustomDevelopedParts, hasBuildPipeline, hasSourcecodeRepo, hasDevOpsClient := false, false, false, false
	for _, technicalAsset := range input.TechnicalAssets {
		getTechFlags(technicalAsset, &hasBuildPipeline, &hasSourcecodeRepo, &hasDevOpsClient)
		if !r.skipAsset(technicalAsset) {
			hasCustomDevelopedParts = true
		}
	}
	hasBuildInfrastructure := hasBuildPipeline && hasSourcecodeRepo && hasDevOpsClient
	if !hasCustomDevelopedParts || hasBuildInfrastructure {
		return []*types.Risk{}, nil
	}
	// A gap in the whole model, so the finding belongs to the system and stays flat at Low, exempt
	// from the CIA step (docs/risk-methodology.md).
	return []*types.Risk{wholeModelRisk(r.Category().ID, "<b>Missing Build Infrastructure</b> in the threat model",
		types.LowImpact)}, nil
}

func (r *MissingBuildInfrastructureRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	if !technicalAsset.CustomDevelopedParts || technicalAsset.OutOfScope {
		return true
	}
	return false
}

func getTechFlags(technicalAsset *types.TechnicalAsset, hasBuildPipeline, hasSourcecodeRepo, hasDevOpsClient *bool) {
	if technicalAsset.Technologies.GetAttribute(types.BuildPipeline) {
		*hasBuildPipeline = true
	}
	if technicalAsset.Technologies.GetAttribute(types.SourcecodeRepository) {
		*hasSourcecodeRepo = true
	}
	if technicalAsset.Technologies.GetAttribute(types.DevOpsClient) {
		*hasDevOpsClient = true
	}
}
