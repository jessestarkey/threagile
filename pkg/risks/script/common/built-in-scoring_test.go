package common

import (
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func callText(t *testing.T, name string, parameters ...Value) string {
	t.Helper()
	result, err := CallBuiltIn(name, parameters...)
	require.NoError(t, err)
	return result.Value().(string)
}

func str(value string) Value { return SomeStringValue(value, nil) }
func num(value int64) Value  { return SomeDecimalValue(decimal.NewFromInt(value), nil) }

func TestAdjustLikelihoodBuiltIn(t *testing.T) {
	assert.Equal(t, "likely", callText(t, adjustLikelihood, str("likely"), num(30)))
	assert.Equal(t, "very-likely", callText(t, adjustLikelihood, str("likely"), num(40)))
	assert.Equal(t, "possible", callText(t, adjustLikelihood, str("likely"), num(10)))
	assert.Equal(t, "possible", callText(t, adjustLikelihood, str("likely"), num(30), num(-1)))
	assert.Equal(t, "possible", callText(t, adjustLikelihood, str("likely"), nil), "missing RAA counts as 0, the low band")
}

func TestAdjustImpactBuiltIn(t *testing.T) {
	assert.Equal(t, "high", callText(t, adjustImpact, str("medium"), str("confidential")))
	assert.Equal(t, "medium", callText(t, adjustImpact, str("medium"), str("restricted")))
	assert.Equal(t, "low", callText(t, adjustImpact, str("medium"), str("")), "missing rating is the zero value")
	assert.Equal(t, "high", callText(t, adjustImpact, str("medium"), str("operational"), str("critical")), "highest rating wins")
	assert.Equal(t, "very-high", callText(t, adjustImpactRank, str("high"), num(4)))
}

func TestCIARankBuiltIn(t *testing.T) {
	result, err := CallBuiltIn(ciaRank, str("mission-critical"))
	require.NoError(t, err)
	assert.True(t, decimal.NewFromInt(4).Equal(result.Value().(decimal.Decimal)))
	result, err = CallBuiltIn(ciaRank, str("internal"), str("critical"), str(""))
	require.NoError(t, err)
	assert.True(t, decimal.NewFromInt(3).Equal(result.Value().(decimal.Decimal)), "highest of several ratings")
}

func TestScoringBuiltInsRejectBadInput(t *testing.T) {
	_, err := CallBuiltIn(adjustLikelihood, str("sometimes"), num(30))
	assert.Error(t, err)
	_, err = CallBuiltIn(adjustImpact, str("medium"))
	assert.Error(t, err)
}
