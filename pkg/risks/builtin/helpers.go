package builtin

import (
	"strings"

	"github.com/threagile/threagile/pkg/types"
)

func isAcrossTrustBoundaryNetworkOnly(parsedModel *types.Model, communicationLink *types.CommunicationLink) bool {

	isAcrossNetworkTrustBoundary := func(
		trustBoundaryOfSourceAsset *types.TrustBoundary, trustBoundaryOfTargetAsset *types.TrustBoundary) bool {
		return trustBoundaryOfSourceAsset.Id != trustBoundaryOfTargetAsset.Id && trustBoundaryOfTargetAsset.Type.IsNetworkBoundary()
	}

	trustBoundaryOfSourceAsset, trustBoundaryOfSourceAssetOk :=
		parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[communicationLink.SourceId]
	if !isNetworkOnly(parsedModel, trustBoundaryOfSourceAssetOk, trustBoundaryOfSourceAsset) {
		return false
	}

	trustBoundaryOfTargetAsset, trustBoundaryOfTargetAssetOk :=
		parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[communicationLink.TargetId]
	if !isNetworkOnly(parsedModel, trustBoundaryOfTargetAssetOk, trustBoundaryOfTargetAsset) {
		return false
	}

	return isAcrossNetworkTrustBoundary(trustBoundaryOfSourceAsset, trustBoundaryOfTargetAsset)
}

func isNetworkOnly(parsedModel *types.Model, trustBoundaryOk bool, trustBoundary *types.TrustBoundary) bool {
	if !trustBoundaryOk {
		return false
	}
	if !trustBoundary.Type.IsNetworkBoundary() { // find and use the parent boundary then
		parentTrustBoundary := parsedModel.FindParentTrustBoundary(trustBoundary)
		if parentTrustBoundary != nil {
			return false
		}
	}
	return true
}

func contains(as []string, b string) bool {
	for _, a := range as {
		if b == a {
			return true
		}
	}
	return false
}

func containsCaseInsensitiveAny(as []string, bs ...string) bool {
	for _, a := range as {
		for _, b := range bs {
			if strings.TrimSpace(strings.ToLower(b)) == strings.TrimSpace(strings.ToLower(a)) {
				return true
			}
		}
	}
	return false
}

func isSameExecutionEnvironment(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {
	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[ta.Id]
	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk {
		return true
	}
	if trustBoundaryOfMyAsset.Type == types.ExecutionEnvironment && trustBoundaryOfOtherAsset.Type == types.ExecutionEnvironment {
		return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
	}
	return false
}

func isSameTrustBoundaryNetworkOnly(parsedModel *types.Model, ta *types.TechnicalAsset, otherAssetId string) bool {

	useParentBoundary := func(trustBoundaryOfAsset **types.TrustBoundary, parsedModel *types.Model, trustBoundaryOfAssetOk *bool) {
		if trustBoundaryOfAsset == nil {
			return
		}
		tb := *trustBoundaryOfAsset
		if tb != nil && !tb.Type.IsNetworkBoundary() {
			*trustBoundaryOfAsset = parsedModel.FindParentTrustBoundary(tb)
			*trustBoundaryOfAssetOk = *trustBoundaryOfAsset != nil
		}
	}

	trustBoundaryOfMyAsset, trustBoundaryOfMyAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[ta.Id]
	useParentBoundary(&trustBoundaryOfMyAsset, parsedModel, &trustBoundaryOfMyAssetOk)

	trustBoundaryOfOtherAsset, trustBoundaryOfOtherAssetOk := parsedModel.DirectContainingTrustBoundaryMappedByTechnicalAssetId[otherAssetId]
	useParentBoundary(&trustBoundaryOfOtherAsset, parsedModel, &trustBoundaryOfOtherAssetOk)

	if trustBoundaryOfMyAssetOk != trustBoundaryOfOtherAssetOk {
		return false
	}
	if !trustBoundaryOfMyAssetOk {
		return true
	}
	return trustBoundaryOfMyAsset.Id == trustBoundaryOfOtherAsset.Id
}

// --- shared risk-scoring helpers ---
//
// These apply the shared scoring steps to a built-in rule's own baseline, the same steps that the
// script rules and inject_risks.py's compute_likelihood() and compute_impact() apply, so a similar
// finding scores the same way in every layer. Each rule keeps its own baseline.

// The RAA thresholds, the CIA-rank deltas and clamping live in pkg/types/risk_scoring.go,
// shared with the script-rule built-ins and mirrored by inject_risks.py.

// strideToCIADimension mirrors STRIDE_TO_CIA_DIMENSION in inject_risks.py: the CIA dimension that a
// finding's STRIDE category threatens, so a denial-of-service finding steps on Availability alone.
// Elevation of privilege, and anything unmapped, uses the highest of the three, since a privileged
// attacker can read, alter, or deny at will.
var strideToCIADimension = map[types.STRIDE]string{
	types.InformationDisclosure: "confidentiality",
	types.Spoofing:              "integrity",
	types.Tampering:             "integrity",
	types.Repudiation:           "integrity",
	types.DenialOfService:       "availability",
}

// computeLikelihood applies the RAA step and the internet step to a rule's baseline, plus any
// rule-specific steps. The internet step (+1, never negative) applies when the asset is
// internet-facing (the native Internet field, on an edge gateway) or carries the author-placed
// net:internet-reachable tag (on the application behind the gateway, which carries Internet:
// false). The two are ORed, since the backend behind a gateway is usually the asset worth
// attacking.
func computeLikelihood(baseline types.RiskExploitationLikelihood, technicalAsset *types.TechnicalAsset, steps ...int) types.RiskExploitationLikelihood {
	exposedDelta := 0
	if technicalAsset.Internet || contains(technicalAsset.Tags, "net:internet-reachable") {
		exposedDelta = 1
	}
	return types.AdjustLikelihood(baseline, technicalAsset.RAA, append([]int{exposedDelta}, steps...)...)
}

// computeImpact applies the symmetric CIA step for the asset's own rank on the dimension that the
// finding's STRIDE category threatens (see strideToCIADimension).
func computeImpact(baseline types.RiskExploitationImpact, stride types.STRIDE, technicalAsset *types.TechnicalAsset) types.RiskExploitationImpact {
	return impactForRatings(baseline, stride, technicalAsset.Confidentiality, technicalAsset.Integrity, technicalAsset.Availability)
}

// rankForStride is the CIA rank (0-4) a finding's STRIDE category threatens: its mapped
// dimension (see strideToCIADimension), or the highest of the three for elevation of privilege
// and anything unmapped.
func rankForStride(stride types.STRIDE, confidentiality types.Confidentiality, integrity, availability types.Criticality) int {
	switch strideToCIADimension[stride] {
	case "confidentiality":
		return int(confidentiality)
	case "integrity":
		return int(integrity)
	case "availability":
		return int(availability)
	}
	return max(int(confidentiality), int(integrity), int(availability))
}

// impactForRatings applies the symmetric CIA step for the given ratings to a baseline.
func impactForRatings(baseline types.RiskExploitationImpact, stride types.STRIDE, confidentiality types.Confidentiality, integrity, availability types.Criticality) types.RiskExploitationImpact {
	return types.AdjustImpactForRank(baseline, rankForStride(stride, confidentiality, integrity, availability))
}

// processedRank is the highest STRIDE-mapped rank across the given assets, counting the data
// they process as well as their own ratings.
func processedRank(input *types.Model, stride types.STRIDE, assets ...*types.TechnicalAsset) int {
	rank := 0
	for _, asset := range assets {
		if asset == nil {
			continue
		}
		rank = max(rank, rankForStride(stride, input.HighestProcessedConfidentiality(asset),
			input.HighestProcessedIntegrity(asset), input.HighestProcessedAvailability(asset)))
	}
	return rank
}

// processedImpact applies the symmetric CIA step for processedRank to a baseline.
func processedImpact(input *types.Model, baseline types.RiskExploitationImpact, stride types.STRIDE, assets ...*types.TechnicalAsset) types.RiskExploitationImpact {
	return types.AdjustImpactForRank(baseline, processedRank(input, stride, assets...))
}

// readAndAlterImpact applies the symmetric CIA step for the higher of the processed
// confidentiality and integrity ranks. Injection, code execution and backdoored code both read
// and alter what the asset handles, so a strictly-confidential but low-integrity asset is not
// rated down just because the category is filed under Tampering. Availability is left out: it is
// not what these threats mainly endanger.
func readAndAlterImpact(input *types.Model, baseline types.RiskExploitationImpact, asset *types.TechnicalAsset) types.RiskExploitationImpact {
	return types.AdjustImpactForRank(baseline, max(int(input.HighestProcessedConfidentiality(asset)), int(input.HighestProcessedIntegrity(asset))))
}

// linkRank is the highest STRIDE-mapped rank of the data carried on the given links.
func linkRank(input *types.Model, stride types.STRIDE, links ...*types.CommunicationLink) int {
	rank := 0
	for _, link := range links {
		if link == nil {
			continue
		}
		rank = max(rank, rankForStride(stride, input.HighestCommunicationLinkConfidentiality(link),
			input.HighestCommunicationLinkIntegrity(link), input.HighestCommunicationLinkAvailability(link)))
	}
	return rank
}

// devOpsStep is the -1 likelihood step for a DevOps-usage link: a build or deployment path is
// reachable by fewer, more trusted callers than a business one.
func devOpsStep(link *types.CommunicationLink) int {
	if link != nil && link.Usage == types.DevOps {
		return -1
	}
	return 0
}

// stepIf returns step when condition holds, else 0.
func stepIf(condition bool, step int) int {
	if condition {
		return step
	}
	return 0
}
