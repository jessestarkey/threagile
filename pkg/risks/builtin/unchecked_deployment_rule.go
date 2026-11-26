package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type UncheckedDeploymentRule struct{}

func NewUncheckedDeploymentRule() *UncheckedDeploymentRule {
	return &UncheckedDeploymentRule{}
}

func (*UncheckedDeploymentRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unchecked-deployment",
		Title: "Unchecked Deployment",
		Description: "For each build-pipeline component Unchecked Deployment risks might arise when the build-pipeline " +
			"does not include established DevSecOps best-practices. DevSecOps best-practices scan as part of CI/CD pipelines for " +
			"vulnerabilities in source- or byte-code, dependencies, container layers, and dynamically against running test systems. " +
			"There are several open-source and commercial tools existing in the categories DAST, SAST, and IAST.",
		Impact: "If this risk remains unmitigated, vulnerabilities in custom-developed software or their dependencies " +
			"might not be identified during continuous deployment cycles.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
		Action: "Add SAST, software composition analysis, secret scanning, IaC scanning, container image scanning, and DAST as " +
			"blocking gates that every artifact must pass before it can reach production.",
		Mitigation: "Run blocking security tests in every build, namely static analysis (Semgrep or CodeQL) on each pull request, software composition analysis with SBOM generation, secret scanning, infrastructure-as-code scanning (Checkov), container image scanning (Trivy), and dynamic testing (OWASP ZAP) against a test environment.\n" +
			"Write a severity policy that blocks promotion on critical and high findings unless a time-bound, documented exception exists, and enforce it in the pipeline.\n" +
			"Have the deployment target or admission controller accept only artifacts with a signed attestation that all gates passed.\n" +
			"Feed findings into vulnerability management and the POA&M, and track time to remediate.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		FindingClass:   types.FindingClassControlNotEvidenced,
		DetectionLogic: "All development-relevant technical assets.",
		RiskAssessment: "The risk rating depends on the highest rating of the technical assets and data assets processed by deployment-receiving targets.",
		FalsePositives: "When the build-pipeline does not build any software components it can be considered a false positive " +
			"after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1127,
	}
}

func (*UncheckedDeploymentRule) SupportedTags() []string {
	return []string{}
}

func (r *UncheckedDeploymentRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.Technologies.GetAttribute(types.IsDevelopmentRelevant) {
			risks = append(risks, r.createRisk(input, technicalAsset))
		}
	}
	return risks, nil
}

func (r *UncheckedDeploymentRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Unchecked Deployment</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact: baseline plus the CIA step on the dimension the STRIDE category threatens, for the
	// deployment targets that receive important-or-higher integrity data.
	rank := 0
	// data breach at all deployment targets
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, codeDeploymentTargetCommLink := range technicalAsset.CommunicationLinks {
		if codeDeploymentTargetCommLink.Usage != types.DevOps {
			continue
		}
		for _, dataAssetID := range codeDeploymentTargetCommLink.DataAssetsSent {
			// it appears to be code when elevated integrity rating of sent data asset
			if input.DataAssets[dataAssetID].Integrity >= types.Important {
				// here we've got a deployment target which has its data assets at risk via deployment of backdoored code
				uniqueDataBreachTechnicalAssetIDs[codeDeploymentTargetCommLink.TargetId] = true
				targetTechAsset := input.TechnicalAssets[codeDeploymentTargetCommLink.TargetId]
				rank = max(rank, processedRank(input, r.Category().STRIDE, targetTechAsset))
				break
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
	impact := types.AdjustImpactForRank(types.LowImpact, rank)
	likelihood := computeLikelihood(types.Likely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
