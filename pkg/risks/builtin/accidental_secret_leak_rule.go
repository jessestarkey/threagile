package builtin

import (
	"fmt"
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

type AccidentalSecretLeakRule struct{}

func NewAccidentalSecretLeakRule() *AccidentalSecretLeakRule {
	return &AccidentalSecretLeakRule{}
}

func (*AccidentalSecretLeakRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "accidental-secret-leak",
		Title: "Accidental Secret Leak",
		Description: "Sourcecode repositories (including their histories) as well as artifact registries can accidentally contain secrets like " +
			"checked-in or packaged-in passwords, API tokens, certificates, crypto keys, etc.",
		Impact: "If this risk is unmitigated, attackers which have access to affected sourcecode repositories or artifact registries might " +
			"find secrets accidentally checked-in.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action: "Block secrets from entering source repositories and artifact registries with pre-commit and server-side push " +
			"scanning, scan the existing history, and revoke and rotate any secret ever found.",
		Mitigation: "Enforce secret scanning at three points: a pre-commit hook on developer workstations (gitleaks, git-secrets, " +
			"or detect-secrets); a server-side push-protection rule on the source repository that rejects commits " +
			"containing known credential formats or high-entropy strings; and a CI stage that scans every build artifact " +
			"and container image layer (trufflehog, gitleaks, or the registry's native scanner) before it is published. " +
			"Keep .gitignore and .dockerignore entries for local credential files (.env, *.pem, *.pfx, kubeconfig, " +
			"terraform.tfstate) and use multi-stage container builds so build-time credentials never persist into a " +
			"published layer. Run a one-time full-history scan of every in-scope repository and registry. Treat any secret " +
			"found as compromised: revoke and rotate it at its issuer first, then purge it from history (git filter-repo " +
			"or BFG), because deleting the file in a new commit leaves it in history and in every existing clone. Replace " +
			"static credentials in code and configuration with references resolved at runtime from a vault or a workload " +
			"identity. References: CWE-798, CWE-540; MITRE ATT&CK T1552.001 (Credentials In Files); NIST SP 800-53 IA-5(7).",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   types.Operations,
		STRIDE:                     types.InformationDisclosure,
		DetectionLogic:             "In-scope sourcecode repositories and artifact registries.",
		RiskAssessment:             "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        200,
	}
}

func (*AccidentalSecretLeakRule) SupportedTags() []string {
	// todo: how is 'nexus' being used?
	return []string{"git", "nexus"}
}

func (r *AccidentalSecretLeakRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if r.skipAsset(techAsset) {
			continue
		}

		var risk *types.Risk
		if techAsset.IsTaggedWithAny("git") {
			risk = r.createRisk(parsedModel, techAsset, "Git", "Git Leak Prevention")
		} else {
			risk = r.createRisk(parsedModel, techAsset, "", "")
		}
		risks = append(risks, risk)
	}
	return risks, nil
}

func (asl AccidentalSecretLeakRule) skipAsset(techAsset *types.TechnicalAsset) bool {
	return techAsset.OutOfScope || !techAsset.Technologies.GetAttribute(types.MayContainSecrets)
}

func (r *AccidentalSecretLeakRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset, prefix, details string) *types.Risk {
	if len(prefix) > 0 {
		prefix = " (" + prefix + ")"
	}
	title := "<b>Accidental Secret Leak" + prefix + "</b> risk at <b>" + technicalAsset.Title + "</b>"
	if len(details) > 0 {
		title += ": <u>" + details + "</u>"
	}
	// Impact intentionally stays keyed off all three CIA dimensions rather than narrowing to
	// just Confidentiality (this category's own STRIDE value): what a leaked secret actually
	// threatens is bounded by what an attacker could do with it -- read, modify, or deny the
	// data it unlocks -- not just disclose it, so a credential guarding Critical/Mission-Critical
	// integrity or availability data deserves the same bump as one guarding Confidential data.
	impact := types.LowImpact
	highestProcessedConfidentiality := parsedModel.HighestProcessedConfidentiality(technicalAsset)
	highestProcessedIntegrity := parsedModel.HighestProcessedIntegrity(technicalAsset)
	highestProcessedAvailability := parsedModel.HighestProcessedAvailability(technicalAsset)
	if highestProcessedConfidentiality >= types.Confidential ||
		highestProcessedIntegrity >= types.Critical ||
		highestProcessedAvailability >= types.Critical {
		impact = types.MediumImpact
	}
	if highestProcessedConfidentiality == types.StrictlyConfidential ||
		highestProcessedIntegrity == types.MissionCritical ||
		highestProcessedAvailability == types.MissionCritical {
		impact = types.HighImpact
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
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}

func (r *AccidentalSecretLeakRule) MatchRisk(parsedModel *types.Model, risk string) bool {
	categoryId := r.Category().ID
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if strings.EqualFold(risk, categoryId+"@"+techAsset.Id) || strings.EqualFold(risk, categoryId+"@*") {
			return true
		}
	}

	return false
}

func (r *AccidentalSecretLeakRule) ExplainRisk(parsedModel *types.Model, risk string) []string {
	categoryId := r.Category().ID
	explanation := make([]string, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		techAsset := parsedModel.TechnicalAssets[id]
		if strings.EqualFold(risk, categoryId+"@"+techAsset.Id) || strings.EqualFold(risk, categoryId+"@*") {
			if !techAsset.OutOfScope && (techAsset.Technologies.GetAttribute(types.SourcecodeRepository) || techAsset.Technologies.GetAttribute(types.ArtifactRegistry)) {
				riskExplanation := r.explainRisk(parsedModel, techAsset)
				if riskExplanation != nil {
					if len(explanation) > 0 {
						explanation = append(explanation, "")
					}

					explanation = append(explanation, []string{
						fmt.Sprintf("technical asset %q", techAsset.Id),
						fmt.Sprintf("  - out of scope: %v (=false)", techAsset.OutOfScope),
						fmt.Sprintf("  - technology: %v (has either [%q, %q])", techAsset.Technologies.String(), types.SourcecodeRepository, types.ArtifactRegistry),
					}...)

					if techAsset.IsTaggedWithAny("git") {
						explanation = append(explanation, "  is tagged with 'git'")
					}

					explanation = append(explanation, riskExplanation...)
				}
			}
		}
	}

	return explanation
}

func (r *AccidentalSecretLeakRule) explainRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) []string {
	explanation := make([]string, 0)
	impact := types.LowImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact

		explanation = append(explanation,
			fmt.Sprintf("    - impact is %v because", impact),
		)

		if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential {
			explanation = append(explanation,
				fmt.Sprintf("      => highest confidentiality: %v (==%v)", parsedModel.HighestProcessedConfidentiality(technicalAsset), types.StrictlyConfidential),
			)
		}

		if parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("      => highest integrity: %v (==%v)", parsedModel.HighestProcessedIntegrity(technicalAsset), types.MissionCritical),
			)
		}

		if parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("      => highest availability: %v (==%v)", parsedModel.HighestProcessedAvailability(technicalAsset), types.MissionCritical),
			)
		}
	} else if parsedModel.HighestProcessedConfidentiality(technicalAsset) >= types.Confidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) >= types.Critical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) >= types.Critical {
		impact = types.MediumImpact
		explanation = append(explanation,
			fmt.Sprintf("    - impact is %v because", impact),
		)

		if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential {
			explanation = append(explanation,
				fmt.Sprintf("     =>  highest confidentiality: %v (>=%v)", parsedModel.HighestProcessedConfidentiality(technicalAsset), types.Confidential),
			)
		}

		if parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("     =>  highest integrity: %v (==%v)", parsedModel.HighestProcessedIntegrity(technicalAsset), types.Critical),
			)
		}

		if parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
			explanation = append(explanation,
				fmt.Sprintf("     =>  highest availability: %v (==%v)", parsedModel.HighestProcessedAvailability(technicalAsset), types.Critical),
			)
		}
	} else {
		explanation = append(explanation,
			fmt.Sprintf("     - impact is %v (default)", impact),
		)
	}

	return explanation
}
