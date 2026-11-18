package script

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

// A rule that states its baseline once and lets the shared built-ins apply the standard steps.
var scoringTestYAML = strings.NewReplacer(
	`severity: "calculate_severity(unlikely, low)"`,
	`severity: "calculate_severity(adjust_likelihood(likely, {tech_asset.raa}), adjust_impact(medium, {tech_asset.confidentiality}))"`,
	`exploitation_likelihood: unlikely`,
	`exploitation_likelihood: "adjust_likelihood(likely, {tech_asset.raa})"`,
	`exploitation_impact: low`,
	`exploitation_impact: "adjust_impact(medium, {tech_asset.confidentiality})"`,
).Replace(minimalTestYAML)

func TestScoringBuiltInsFromAScriptRule(t *testing.T) {
	cases := []struct {
		name            string
		raa             float64
		confidentiality types.Confidentiality
		likelihood      types.RiskExploitationLikelihood
		impact          types.RiskExploitationImpact
	}{
		{"mid RAA, confidential", 30, types.Confidential, types.Likely, types.HighImpact},
		{"high RAA, restricted", 55, types.Restricted, types.VeryLikely, types.MediumImpact},
		{"low RAA, public (dropped zero value)", 5, types.Public, types.PossibleLikelihood, types.LowImpact},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := new(RiskRule).Init()
			_, err := rule.ParseFromData([]byte(scoringTestYAML))
			require.NoError(t, err)
			model := &types.Model{TechnicalAssets: map[string]*types.TechnicalAsset{
				"ta1": {Id: "ta1", Title: "Asset", RAA: tc.raa, Confidentiality: tc.confidentiality},
			}}
			risks, err := rule.GenerateRisks(model)
			require.NoError(t, err)
			require.Len(t, risks, 1)
			assert.Equal(t, tc.likelihood, risks[0].ExploitationLikelihood)
			assert.Equal(t, tc.impact, risks[0].ExploitationImpact)
			assert.Equal(t, types.CalculateSeverity(tc.likelihood, tc.impact), risks[0].Severity)
		})
	}
}
