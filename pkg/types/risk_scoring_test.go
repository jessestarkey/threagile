package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdjustLikelihoodAppliesRAAAndStepsClamped(t *testing.T) {
	assert.Equal(t, Likely, AdjustLikelihood(Likely, 30))
	assert.Equal(t, VeryLikely, AdjustLikelihood(Likely, 40))
	assert.Equal(t, PossibleLikelihood, AdjustLikelihood(Likely, 14.9))
	assert.Equal(t, PossibleLikelihood, AdjustLikelihood(Likely, 30, -1))
	assert.Equal(t, VeryLikely, AdjustLikelihood(VeryLikely, 90, 1), "clamped at the ceiling")
	assert.Equal(t, Unlikely, AdjustLikelihood(Unlikely, 5, -1), "clamped at the floor")
}

func TestAdjustImpactForRankIsSymmetric(t *testing.T) {
	assert.Equal(t, LowImpact, AdjustImpactForRank(MediumImpact, 0))
	assert.Equal(t, LowImpact, AdjustImpactForRank(MediumImpact, 1))
	assert.Equal(t, MediumImpact, AdjustImpactForRank(MediumImpact, 2))
	assert.Equal(t, HighImpact, AdjustImpactForRank(MediumImpact, 3))
	assert.Equal(t, HighImpact, AdjustImpactForRank(MediumImpact, 4))
	assert.Equal(t, VeryHighImpact, AdjustImpactForRank(VeryHighImpact, 4), "clamped at the ceiling")
	assert.Equal(t, LowImpact, AdjustImpactForRank(LowImpact, 0), "clamped at the floor")
}

func TestCIARankParsesBothScales(t *testing.T) {
	assert.Equal(t, 0, CIARank(""), "missing rating is the zero value (public / archive)")
	assert.Equal(t, 0, CIARank("public"))
	assert.Equal(t, 2, CIARank("restricted"))
	assert.Equal(t, 3, CIARank("confidential"))
	assert.Equal(t, 4, CIARank("strictly-confidential"))
	assert.Equal(t, 1, CIARank("operational"))
	assert.Equal(t, 2, CIARank("important"))
	assert.Equal(t, 4, CIARank("mission-critical"))
	assert.Equal(t, 0, CIARank("nonsense"))
}
