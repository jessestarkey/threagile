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
		Mitigation: "Integrate automated security testing into every build: static analysis (Semgrep, CodeQL, SonarQube, Fortify) " +
			"on each pull request; software composition analysis (OWASP Dependency-Check, Dependabot, Grype, Snyk) over " +
			"the full dependency tree with SBOM generation; secret scanning; infrastructure-as-code scanning (Checkov, " +
			"tfsec, KICS); container image scanning (Trivy, Anchore); and dynamic testing (OWASP ZAP, Burp Suite " +
			"Enterprise) against a deployed test environment. Define a written severity policy that blocks promotion on " +
			"critical and high findings unless a time-bound, documented exception exists, and enforce it in the pipeline " +
			"rather than by convention. Require the deployment target or admission controller to accept only artifacts " +
			"carrying a signed attestation that all gates passed. Feed findings into vulnerability management and the " +
			"POA&M, and track time to remediate. References: CWE-1395, CWE-1104; MITRE ATT&CK T1195.001 (Compromise " +
			"Software Dependencies and Development Tools); OWASP Top 10:2025 A03 (Software Supply Chain Failures); NIST SP " +
			"800-218 (SSDF) PW.7, PW.8, RV.1; NIST SP 800-53 SA-11, RA-5.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
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
	// Impact intentionally stays keyed off all three CIA dimensions rather than narrowing to
	// just Integrity (this category's own STRIDE value): an unscanned vulnerability shipped to a
	// deployment target can threaten any of its CIA dimensions, not just integrity.
	// impact is depending on highest rating
	impact := types.LowImpact
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
				if input.HighestProcessedConfidentiality(targetTechAsset) >= types.Confidential ||
					input.HighestProcessedIntegrity(targetTechAsset) >= types.Critical ||
					input.HighestProcessedAvailability(targetTechAsset) >= types.Critical {
					impact = types.MediumImpact
				}
				break
			}
		}
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	// create risk
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
