package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

func customCategoryModel(findingClass string) *input.Model {
	asset := createTechnicalAsset(types.Confidential, types.Critical, types.Important)
	asset.ID = "ta"
	model := createInputModel(map[string]input.TechnicalAsset{"TA": asset}, map[string]input.DataAsset{})
	model.CustomRiskCategories = input.RiskCategories{{
		ID:           "custom-category",
		Title:        "Custom Category",
		Function:     "architecture",
		STRIDE:       "tampering",
		FindingClass: findingClass,
		RisksIdentified: map[string]input.RiskIdentified{
			"Custom finding at TA": {
				Severity:                   "elevated",
				ExploitationLikelihood:     "likely",
				ExploitationImpact:         "medium",
				DataBreachProbability:      "possible",
				MostRelevantTechnicalAsset: "ta",
			},
		},
	}}
	return model
}

func TestCustomCategoryFindingClassReachesCategoryAndRisks(t *testing.T) {
	parsed, err := ParseModel(&mockConfig{}, customCategoryModel(types.FindingClassWeaknessShown), make(types.RiskRules), make(types.RiskRules))
	require.NoError(t, err)

	category := parsed.GetRiskCategory("custom-category")
	require.NotNil(t, category)
	assert.Equal(t, types.FindingClassWeaknessShown, category.FindingClass)
	require.Len(t, parsed.GeneratedRisksByCategory["custom-category"], 1)
	assert.Equal(t, types.FindingClassWeaknessShown, parsed.GeneratedRisksByCategory["custom-category"][0].FindingClass)
}

func TestCustomCategoryRejectsAnUnknownFindingClass(t *testing.T) {
	_, err := ParseModel(&mockConfig{}, customCategoryModel("probably-fine"), make(types.RiskRules), make(types.RiskRules))
	assert.ErrorContains(t, err, "finding_class")
}

type quietReporter struct{}

func (quietReporter) Info(...any)           {}
func (quietReporter) Warn(...any)           {}
func (quietReporter) Error(...any)          {}
func (quietReporter) Infof(string, ...any)  {}
func (quietReporter) Warnf(string, ...any)  {}
func (quietReporter) Errorf(string, ...any) {}

type classedRule struct{ category types.RiskCategory }

func (r *classedRule) Category() *types.RiskCategory { return &r.category }
func (r *classedRule) SupportedTags() []string       { return nil }
func (r *classedRule) GenerateRisks(*types.Model) ([]*types.Risk, error) {
	return []*types.Risk{{CategoryId: r.category.ID, SyntheticId: r.category.ID + "@x"}}, nil
}

func TestGeneratedRisksInheritTheirRuleCategoryFindingClass(t *testing.T) {
	parsed := &types.Model{
		GeneratedRisksByCategory:    map[string][]*types.Risk{},
		GeneratedRisksBySyntheticId: map[string]*types.Risk{},
	}
	rule := &classedRule{types.RiskCategory{ID: "rule-x", FindingClass: types.FindingClassControlNotEvidenced}}
	parsed.BuiltInRiskCategories = types.RiskCategories{rule.Category()}

	applyRiskGeneration(parsed, types.RiskRules{"rule-x": rule}, nil, quietReporter{})

	require.Len(t, parsed.GeneratedRisksByCategory["rule-x"], 1)
	assert.Equal(t, types.FindingClassControlNotEvidenced, parsed.GeneratedRisksByCategory["rule-x"][0].FindingClass)
}
