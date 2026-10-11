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
		Action: "Validate every uploaded file server-side by allowlisted type, content signature, and size; rename it; " +
			"malware-scan it; and store it outside the web root.",
		Mitigation: "Accept only an explicit allowlist of file extensions required by the business function, and confirm the real " +
			"content type server-side from the file's magic bytes (Apache Tika, libmagic), never from the client-supplied " +
			"Content-Type header or filename. Discard the client filename and store the file under a server-generated " +
			"random identifier, keeping the original name only as escaped metadata. Enforce a maximum file size at both " +
			"the reverse proxy and the application, plus limits on archive decompression ratio, entry count, and nesting " +
			"depth to stop zip bombs, and reject archive entries with absolute paths or parent-directory segments (Zip " +
			"Slip). Scan every file with an anti-malware engine (ClamAV, Defender for Storage malware scanning, or a " +
			"commercial engine) before it becomes retrievable, and rescan on retrieval when files can be served long after " +
			"upload. Store uploads outside the web root or in object storage with no execute permission, and serve them " +
			"with Content-Disposition attachment and X-Content-Type-Options nosniff from a separate origin. Consider " +
			"content disarm and reconstruction for Office and PDF files that users will open. References: CWE-434, " +
			"CWE-409; CAPEC-17 (Using Malicious Files); OWASP Top 10:2025 A06 (Insecure Design).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
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
	// Impact intentionally stays keyed off all three CIA dimensions rather than narrowing to
	// just Integrity (this category's own STRIDE value): a malicious uploaded file can carry
	// malware (an availability/integrity threat) or be crafted to exfiltrate data via a
	// processing vulnerability (a confidentiality threat), not just one.
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		input.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood := computeLikelihood(types.Likely, technicalAsset)
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
