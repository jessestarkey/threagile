package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type PathTraversalRule struct{}

func NewPathTraversalRule() *PathTraversalRule {
	return &PathTraversalRule{}
}

func (*PathTraversalRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "path-traversal",
		Title: "Path-Traversal",
		Description: "When a filesystem is accessed Path-Traversal or Local-File-Inclusion (LFI) risks might arise. " +
			"The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		Impact: "If this risk is unmitigated, attackers might be able to read sensitive files (configuration data, key/credential files, deployment files, " +
			"business data files, etc.) from the filesystem of affected components.",
		ASVS:       "V12 - File and Resources Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
		Action: "Resolve every caller-influenced file path to its canonical form and verify it stays inside an allowlisted " +
			"base directory, or replace caller-supplied filenames with server-side identifiers.",
		Mitigation: "Prefer indirect references, mapping a caller-supplied identifier to a server-side filename so the caller never supplies a path.\n" +
			"Where a filename must be accepted, allow only letters, digits, hyphens, underscores, and one permitted extension, and reject separators, parent-directory segments, NUL bytes, and their encoded forms.\n" +
			"Canonicalize the joined path (realpath or Path.GetFullPath), and confirm it still begins with the intended base directory before opening it.\n" +
			"Run the process under an account whose filesystem permissions exclude configuration, key, and credential files, and use a read-only root filesystem in containers.\n" +
			"Apply the same checks to archive extraction (Zip Slip) and to template or include directives (local file inclusion).\n" +
			"For third-party products, confirm the vendor's path handling, and keep the product patched.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.InformationDisclosure,
		FindingClass:   types.FindingClassControlNotEvidenced,
		DetectionLogic: "Filesystems accessed by in-scope callers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the technical asset.",
		FalsePositives: "File accesses by filenames not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        22,
	}
}

func (*PathTraversalRule) SupportedTags() []string {
	return []string{}
}

func (r *PathTraversalRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.Technologies.GetAttribute(types.IsFileStorage) {
			continue
		}
		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			likelihood := computeLikelihood(types.Likely, technicalAsset, devOpsStep(incomingFlow))
			risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow, likelihood))
		}
	}
	return risks, nil
}

func (r *PathTraversalRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink, likelihood types.RiskExploitationLikelihood) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Path-Traversal</b> risk at <b>" + caller.Title + "</b> against filesystem <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	// Confidentiality alone, matching the STRIDE category, since path traversal reads files rather
	// than modifying them.
	impact := processedImpact(input, types.MediumImpact, r.Category().STRIDE, technicalAsset)
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
