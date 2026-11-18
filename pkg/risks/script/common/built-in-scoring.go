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
// Missing values (dropped zero values such as public, archive, or RAA 0) count as 0.

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
	highest := 0
	for _, parameter := range parameters[1:] {
		if rank := types.CIARank(textArg(parameter)); rank > highest {
			highest = rank
		}
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
	highest := 0
	for _, parameter := range parameters {
		if rank := types.CIARank(textArg(parameter)); rank > highest {
			highest = rank
		}
	}
	return SomeDecimalValue(decimal.NewFromInt(int64(highest)), nil), nil
}
