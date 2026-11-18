package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseMissionCriticalityAcceptsTheFourValuesAndMapsTheOldFive(t *testing.T) {
	for value, want := range map[string]MissionCriticality{
		"administrative":    MissionCriticalityAdministrative,
		"mission-support":   MissionCriticalitySupport,
		"mission-essential": MissionCriticalityEssential,
		"mission-critical":  MissionCriticalityCritical,
		"Mission-Essential": MissionCriticalityEssential,
	} {
		got, legacy, err := ParseMissionCriticality(value)
		require.NoError(t, err, value)
		assert.Equal(t, want, got, value)
		assert.False(t, legacy, value)
	}
	for value, want := range map[string]MissionCriticality{
		"archive":     MissionCriticalityAdministrative,
		"operational": MissionCriticalityAdministrative,
		"important":   MissionCriticalitySupport,
		"critical":    MissionCriticalityEssential,
	} {
		got, legacy, err := ParseMissionCriticality(value)
		require.NoError(t, err, value)
		assert.Equal(t, want, got, value)
		assert.True(t, legacy, "%s is an older value", value)
	}
	_, _, err := ParseMissionCriticality("mission support")
	assert.Error(t, err, "values are hyphenated")
}

func TestMissionCriticalityNamesAndYAML(t *testing.T) {
	assert.Equal(t, "mission-support", MissionCriticalitySupport.String())
	assert.Equal(t, "Mission Support", MissionCriticalitySupport.Title())
	var value MissionCriticality
	require.NoError(t, yaml.Unmarshal([]byte("critical"), &value))
	assert.Equal(t, MissionCriticalityEssential, value, "older values unmarshal through the mapping")
	out, err := yaml.Marshal(MissionCriticalityEssential)
	require.NoError(t, err)
	assert.Equal(t, "mission-essential\n", string(out))
}
