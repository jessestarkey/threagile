package types

import "strings"

// Shared per-asset scoring arithmetic for every rule layer (built-in Go rules and script rules;
// the custom Python engine in central-security-repo mirrors these values -- see
// docs/risk-methodology.md, "Risk calibration" and "Keeping this in sync").
//
// Likelihood: baseline, plus a -1/0/+1 step from the asset's RAA, plus any rule-specific steps.
// Impact: baseline, plus a -1/0/+1 step from a CIA rank (0-4, Confidentiality and Criticality
// share the same ordinal shape): -1 for rank 0-1, 0 for rank 2, +1 for rank 3-4.

const (
	RAALikelihoodThreshold    = 40.0 // RAA at or above this: +1 likelihood
	RAALikelihoodLowThreshold = 15.0 // RAA below this: -1 likelihood
)

// CIARankToDelta maps a CIA rank (0-4) to its impact step.
var CIARankToDelta = [...]int{-1, -1, 0, 1, 1}

// ClampLikelihood keeps an ordinal likelihood index within Unlikely..VeryLikely.
func ClampLikelihood(index int) RiskExploitationLikelihood {
	if index < int(Unlikely) {
		return Unlikely
	}
	if index > int(VeryLikely) {
		return VeryLikely
	}
	return RiskExploitationLikelihood(index)
}

// ClampImpact keeps an ordinal impact index within Low..VeryHigh.
func ClampImpact(index int) RiskExploitationImpact {
	if index < int(LowImpact) {
		return LowImpact
	}
	if index > int(VeryHighImpact) {
		return VeryHighImpact
	}
	return RiskExploitationImpact(index)
}

// RAALikelihoodDelta is the -1/0/+1 likelihood step from an asset's RAA.
func RAALikelihoodDelta(raa float64) int {
	if raa >= RAALikelihoodThreshold {
		return 1
	}
	if raa < RAALikelihoodLowThreshold {
		return -1
	}
	return 0
}

// AdjustLikelihood applies the RAA step and any rule-specific steps to a baseline, clamped.
func AdjustLikelihood(baseline RiskExploitationLikelihood, raa float64, steps ...int) RiskExploitationLikelihood {
	index := int(baseline) + RAALikelihoodDelta(raa)
	for _, step := range steps {
		index += step
	}
	return ClampLikelihood(index)
}

// CIARankDelta is the -1/0/+1 impact step for a CIA rank; ranks outside 0-4 are clamped.
func CIARankDelta(rank int) int {
	if rank < 0 {
		rank = 0
	}
	if rank > len(CIARankToDelta)-1 {
		rank = len(CIARankToDelta) - 1
	}
	return CIARankToDelta[rank]
}

// AdjustImpactForRank applies the CIA step for a rank to a baseline, clamped.
func AdjustImpactForRank(baseline RiskExploitationImpact, rank int) RiskExploitationImpact {
	return ClampImpact(int(baseline) + CIARankDelta(rank))
}

// CIARank parses a Confidentiality or Criticality name ("confidential", "mission-critical", ...)
// into its 0-4 rank. An empty or unknown value is rank 0: public and archive are the zero values
// and are dropped from serialized models, so a missing rating means the lowest one.
func CIARank(value string) int {
	rank, _ := ParseCIARank(value)
	return rank
}

// ParseCIARank is CIARank that also reports whether value was understood: empty (a dropped zero
// value) and any confidentiality or criticality name are; anything else, such as a misspelling,
// is not.
func ParseCIARank(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, true
	}
	if confidentiality, err := Confidentiality(0).Find(value); err == nil {
		return int(confidentiality), true
	}
	if criticality, err := Criticality(0).Find(value); err == nil {
		return int(criticality), true
	}
	return 0, false
}
