package builtin

import (
	"strconv"

	"github.com/threagile/threagile/pkg/types"
)

type MissingHardeningRule struct {
	raaLimit        int
	raaLimitReduced int
}

func NewMissingHardeningRule() *MissingHardeningRule {
	return &MissingHardeningRule{raaLimit: 55, raaLimitReduced: 40}
}

func (r *MissingHardeningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-hardening",
		Title: "Missing Hardening",
		Description: "Technical assets with a Relative Attacker Attractiveness (RAA) value of " + strconv.Itoa(r.raaLimit) + " % or higher should be " +
			"explicitly hardened taking best practices and vendor hardening guides into account.",
		Impact:     "If this risk remains unmitigated, attackers might be able to easier attack high-value targets.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "System Hardening",
		Mitigation: "Try to apply all hardening best practices (like CIS benchmarks, OWASP recommendations, vendor " +
			"recommendations, DevSec Hardening Framework, DBSAT for Oracle databases, and others).",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Operations,
		STRIDE:   types.Tampering,
		DetectionLogic: "In-scope technical assets with RAA values of " + strconv.Itoa(r.raaLimit) + " % or higher. " +
			"Generally for high-value targets like data stores, application servers, identity providers and ERP systems this limit is reduced to " + strconv.Itoa(r.raaLimitReduced) + " %",
		RiskAssessment:             "The risk rating depends on the sensitivity of the data processed in the technical asset.",
		FalsePositives:             "Usually no false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        16,
	}
}

func (*MissingHardeningRule) SupportedTags() []string {
	return []string{"tomcat"}
}

func (r *MissingHardeningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		if technicalAsset.RAA >= float64(r.raaLimit) ||
			(technicalAsset.RAA >= float64(r.raaLimitReduced) &&
				(technicalAsset.Type == types.Datastore || technicalAsset.Technologies.GetAttribute(types.IsHighValueTarget))) {
			risks = append(risks, r.createRisk(input, technicalAsset))
		}
	}
	return risks, nil
}

func (r *MissingHardeningRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope
}

func (r *MissingHardeningRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing Hardening</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact intentionally stays keyed off both Confidentiality and Integrity rather than
	// narrowing to just Integrity (this category's own STRIDE value): this category's own
	// Impact text is generically about attacking a high-value target, not a single dimension.
	impact := types.LowImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.MediumImpact
	}
	// RAA already decides whether this risk fires at all (see GenerateRisks's raaLimit/
	// raaLimitReduced gate) -- that detection-logic role is kept as-is. computeLikelihood() is
	// still applied on top of the flat baseline for consistency with every other rule's scoring:
	// since both raaLimit (55) and raaLimitReduced (40) already sit at or above
	// raaLikelihoodThreshold (40), every asset that reaches this point already earns the RAA
	// Likelihood delta too, so Likely becomes VeryLikely here consistently -- the reachability
	// delta can still vary per asset even though the RAA delta cannot.
	likelihood := computeLikelihood(types.Likely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
