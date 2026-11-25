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

// asset is a technical asset as the script engine passes it, a map of its JSON fields.
func asset(fields map[string]any) Value { return SomeValue(fields, nil) }

func TestAdjustLikelihoodBuiltIn(t *testing.T) {
	assert.Equal(t, "likely", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 30.0})))
	assert.Equal(t, "very-likely", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 40.0})))
	assert.Equal(t, "possible", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 10.0})))
	assert.Equal(t, "possible", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 30.0}), num(-1)))
	assert.Equal(t, "possible", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{})), "missing RAA counts as 0, the low band")
}

func TestAdjustLikelihoodTakesTheInternetStep(t *testing.T) {
	for _, field := range []string{"internet", "internet_reachable"} {
		assert.Equal(t, "very-likely", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 30.0, field: true})), field)
	}
	assert.Equal(t, "likely", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 30.0, "internet": false})))
	assert.Equal(t, "likely", callText(t, adjustLikelihood, str("likely"), asset(map[string]any{"raa": 10.0, "internet": true})),
		"the low RAA band and the internet step cancel out, as in the built-in rules")
	_, err := CallBuiltIn(adjustLikelihood, str("likely"), num(30))
	assert.ErrorContains(t, err, "expected the technical asset", "a bare RAA must not silently skip the internet step")
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
	_, err := CallBuiltIn(adjustLikelihood, str("sometimes"), asset(map[string]any{"raa": 30.0}))
	assert.Error(t, err)
	_, err = CallBuiltIn(adjustImpact, str("medium"))
	assert.Error(t, err)
	_, err = CallBuiltIn(adjustLikelihood, str(""), asset(map[string]any{"raa": 30.0}))
	assert.ErrorContains(t, err, "missing baseline")
	_, err = CallBuiltIn(adjustImpact, str(""), str("confidential"))
	assert.ErrorContains(t, err, "missing baseline")
	_, err = CallBuiltIn(adjustImpact, str("medium"), str("confidental"))
	assert.ErrorContains(t, err, "unknown rating", "a misspelled rating must not become rank 0")
	_, err = CallBuiltIn(adjustImpact, str("medium"), num(3))
	assert.ErrorContains(t, err, "adjust_impact_rank", "a rank passed to adjust_impact must not become rank 0")
	_, err = CallBuiltIn(ciaRank, str("critcal"))
	assert.ErrorContains(t, err, "unknown rating")
}
