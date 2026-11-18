package common

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/threagile/threagile/pkg/types"
)

// Script-language wrappers around the shared scoring arithmetic in pkg/types/risk_scoring.go, so
// every script rule states its baseline once and applies the standard steps the same way:
//
//	adjust_likelihood(baseline, raa, steps...)  baseline + RAA step + each step, clamped
//	adjust_impact(baseline, ratings...)          baseline + CIA step for the highest rating given
//	adjust_impact_rank(baseline, rank)           baseline + CIA step for a 0-4 rank
//	cia_rank(ratings...)                         highest 0-4 rank among confidentiality/criticality names
//
// Missing values (dropped zero values such as public, archive, or RAA 0) count as 0. A missing
// baseline, an unknown rating name, or a number passed as a rating is an error rather than a
// silent rank 0, so a typo in a rule fails loudly instead of rating one level low.

const (
	adjustLikelihood = "adjust_likelihood"
	adjustImpact     = "adjust_impact"
	adjustImpactRank = "adjust_impact_rank"
	ciaRank          = "cia_rank"
)

func init() {
	callers[adjustLikelihood] = adjustLikelihoodFunc
	callers[adjustImpact] = adjustImpactFunc
	callers[adjustImpactRank] = adjustImpactRankFunc
	callers[ciaRank] = ciaRankFunc
}

func plainValue(value Value) any {
	if value == nil {
		return nil
	}
	plain := value.Value()
	if inner, ok := plain.(Value); ok {
		return plainValue(inner)
	}
	return plain
}

func numberArg(value Value) (float64, error) {
	switch v := plainValue(value).(type) {
	case nil:
		return 0, nil
	case decimal.Decimal:
		return v.InexactFloat64(), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case float64:
		return v, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, nil
		}
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	default:
		return 0, fmt.Errorf("expected a number, got %T", v)
	}
}

func textArg(value Value) string {
	switch v := plainValue(value).(type) {
	case nil:
		return ""
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func adjustLikelihoodFunc(parameters []Value) (Value, error) {
	if len(parameters) < 2 {
		return nil, fmt.Errorf("%s: expected baseline and raa, got %d parameters", adjustLikelihood, len(parameters))
	}
	if strings.TrimSpace(textArg(parameters[0])) == "" {
		return nil, fmt.Errorf("%s: missing baseline", adjustLikelihood)
	}
	baseline, err := types.RiskExploitationLikelihood(0).Find(strings.TrimSpace(textArg(parameters[0])))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", adjustLikelihood, err)
	}
	raa, err := numberArg(parameters[1])
	if err != nil {
		return nil, fmt.Errorf("%s: raa: %w", adjustLikelihood, err)
	}
	steps := make([]int, 0, len(parameters)-2)
	for _, parameter := range parameters[2:] {
		step, stepErr := numberArg(parameter)
		if stepErr != nil {
			return nil, fmt.Errorf("%s: step: %w", adjustLikelihood, stepErr)
		}
		steps = append(steps, int(step))
	}
	return SomeStringValue(types.AdjustLikelihood(baseline, raa, steps...).String(), nil), nil
}

func impactBaseline(name string, value Value) (types.RiskExploitationImpact, error) {
	if strings.TrimSpace(textArg(value)) == "" {
		return types.LowImpact, fmt.Errorf("%s: missing baseline", name)
	}
	baseline, err := types.RiskExploitationImpact(0).Find(strings.TrimSpace(textArg(value)))
	if err != nil {
		return baseline, fmt.Errorf("%s: %w", name, err)
	}
	return baseline, nil
}

func adjustImpactFunc(parameters []Value) (Value, error) {
	if len(parameters) < 2 {
		return nil, fmt.Errorf("%s: expected baseline and at least one rating, got %d parameters", adjustImpact, len(parameters))
	}
	baseline, err := impactBaseline(adjustImpact, parameters[0])
	if err != nil {
		return nil, err
	}
	highest, err := highestRating(adjustImpact, parameters[1:])
	if err != nil {
		return nil, err
	}
	return SomeStringValue(types.AdjustImpactForRank(baseline, highest).String(), nil), nil
}

func adjustImpactRankFunc(parameters []Value) (Value, error) {
	if len(parameters) != 2 {
		return nil, fmt.Errorf("%s: expected baseline and rank, got %d parameters", adjustImpactRank, len(parameters))
	}
	baseline, err := impactBaseline(adjustImpactRank, parameters[0])
	if err != nil {
		return nil, err
	}
	rank, err := numberArg(parameters[1])
	if err != nil {
		return nil, fmt.Errorf("%s: rank: %w", adjustImpactRank, err)
	}
	return SomeStringValue(types.AdjustImpactForRank(baseline, int(rank)).String(), nil), nil
}

func ciaRankFunc(parameters []Value) (Value, error) {
	if len(parameters) < 1 {
		return nil, fmt.Errorf("%s: expected at least one rating", ciaRank)
	}
	highest, err := highestRating(ciaRank, parameters)
	if err != nil {
		return nil, err
	}
	return SomeDecimalValue(decimal.NewFromInt(int64(highest)), nil), nil
}

// highestRating is the highest 0-4 rank among confidentiality/criticality names. A number is
// rejected (a rank belongs in adjust_impact_rank), as is any name that is not a rating.
func highestRating(name string, parameters []Value) (int, error) {
	highest := 0
	for _, parameter := range parameters {
		switch plainValue(parameter).(type) {
		case decimal.Decimal, int, int64, float64:
			return 0, fmt.Errorf("%s: got a number where a rating name belongs (use adjust_impact_rank for a rank)", name)
		}
		rank, ok := types.ParseCIARank(textArg(parameter))
		if !ok {
			return 0, fmt.Errorf("%s: unknown rating %q", name, textArg(parameter))
		}
		highest = max(highest, rank)
	}
	return highest, nil
}
