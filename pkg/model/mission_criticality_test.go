package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

func missionModel(mission, business string) *input.Model {
	model := createInputModel(map[string]input.TechnicalAsset{}, map[string]input.DataAsset{})
	model.MissionCriticality, model.BusinessCriticality = mission, business
	return model
}

func TestMissionCriticalityKeyAndItsOlderName(t *testing.T) {
	for _, tc := range []struct {
		name, mission, business string
		want                    types.MissionCriticality
	}{
		{"new key", "mission-essential", "", types.MissionCriticalityEssential},
		{"older key, older value", "", "critical", types.MissionCriticalityEssential},
		{"older key, new value", "", "mission-support", types.MissionCriticalitySupport},
		{"both keys agreeing", "mission-critical", "mission-critical", types.MissionCriticalityCritical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseModel(&mockConfig{}, missionModel(tc.mission, tc.business), make(types.RiskRules), make(types.RiskRules))
			require.NoError(t, err)
			assert.Equal(t, tc.want, parsed.MissionCriticality)
		})
	}

	_, err := ParseModel(&mockConfig{}, missionModel("administrative", "mission-critical"), make(types.RiskRules), make(types.RiskRules))
	assert.ErrorContains(t, err, "disagree")
	_, err = ParseModel(&mockConfig{}, missionModel("vital", ""), make(types.RiskRules), make(types.RiskRules))
	assert.ErrorContains(t, err, "mission_criticality")
}
