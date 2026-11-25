package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingFileValidationRule struct{}

func NewMissingFileValidationRule() *MissingFileValidationRule {
	return &MissingFileValidationRule{}
}

func (*MissingFileValidationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "missing-file-validation",
		Title:       "Missing File Validation",
		Description: "When a technical asset accepts files, these input files should be strictly validated about filename and type.",
		Impact:      "If this risk is unmitigated, attackers might be able to provide malicious files to the application.",
		ASVS:        "V12 - File and Resources Verification Requirements",
		CheatSheet:  "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
		Action:      "Validate every uploaded file server-side by allowlisted type, content signature, and size, then rename it, scan it for malware, and store it outside the web root.",
		Mitigation: "Accept only an allowlist of the file types that the business function needs, and confirm each file's real type server-side from its magic bytes (Apache Tika or libmagic), never from the client's Content-Type or filename.\n" +
			"Store each file under a server-generated identifier, keeping the original name only as escaped metadata.\n" +
			"Enforce a maximum file size at the proxy and the application, limit archive decompression ratio, entry count, and nesting depth, and reject archive entries with absolute or parent-directory paths (Zip Slip).\n" +
			"Scan every file for malware before it becomes retrievable, and rescan on retrieval when files are served long after upload.\n" +
			"Store uploads outside the web root with no execute permission, and serve them from a separate origin with Content-Disposition attachment and X-Content-Type-Options nosniff.\n" +
			"Consider content disarm and reconstruction for Office and PDF files that users will open.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		FindingClass:   types.FindingClassControlNotEvidenced,
		DetectionLogic: "In-scope technical assets with custom-developed code accepting file data formats.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) files can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        434,
	}
}

func (*MissingFileValidationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingFileValidationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.File {
				risks = append(risks, r.createRisk(input, technicalAsset))
			}
		}
	}
	return risks, nil
}

func (r *MissingFileValidationRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope || !technicalAsset.CustomDevelopedParts
}

func (r *MissingFileValidationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing File Validation</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact: baseline plus the CIA step on the dimension the STRIDE category threatens, for the data
	// the asset processes.
	impact := processedImpact(input, types.MediumImpact, r.Category().STRIDE, technicalAsset)
	likelihood := computeLikelihood(types.PossibleLikelihood, technicalAsset)
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
