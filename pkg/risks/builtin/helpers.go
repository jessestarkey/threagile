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
// computeLikelihood/computeImpact below mirror compute_likelihood()/compute_impact() in
// models/central-security-repo/core-policies/inject_risks.py -- the custom risk-injection engine
// that runs on this model before Threagile itself does. That engine nudges each custom category's
// own author-judged baseline Likelihood/Impact by real per-asset context (RAA, internet
// reachability, the specific CIA dimension a finding's STRIDE category threatens, gated business
// criticality) rather than using a flat value for every asset a category fires on. These two
// functions let built-in rules apply the identical nudges on top of their own existing hardcoded
// baseline, so a similar-looking finding scores consistently whichever engine produced it -- they
// do not change what counts as a baseline; each rule keeps its own judgment call about that.

// raaLikelihoodThreshold/raaLikelihoodLowThreshold match RAA_LIKELIHOOD_THRESHOLD/
// RAA_LIKELIHOOD_LOW_THRESHOLD in inject_risks.py exactly -- kept identical so a finding's
// RAA-driven Likelihood delta behaves the same regardless of which engine computed it.
// Both now live in pkg/types/risk_scoring.go, shared with the script-rule built-ins.
const raaLikelihoodThreshold = types.RAALikelihoodThreshold
const raaLikelihoodLowThreshold = types.RAALikelihoodLowThreshold

// ciaRankToDelta maps a CIA rank (Confidentiality's and Criticality's shared 0-4 ordinal shape --
// Criticality covers both Integrity and Availability) to the -1/0/+1 Impact delta applied on top
// of a baseline. Mirrors CIA_RANK_TO_DELTA in inject_risks.py: the bottom two tiers pull the
// baseline down a notch, the middle tier leaves it alone, the top two tiers push it up a notch.
var ciaRankToDelta = types.CIARankToDelta

// strideToCIADimension mirrors STRIDE_TO_CIA_DIMENSION in inject_risks.py: which CIA dimension a
// finding's STRIDE category most directly threatens, so e.g. a denial-of-service finding is nudged
// by Availability alone rather than a flat max(C,I,A). ElevationOfPrivilege, and any STRIDE value
// not listed here, falls back to the max of all three (same as the Python side's dict .get()
// default), since a privileged attacker can read, alter, or deny at will regardless of which single
// dimension the category happens to be filed under.
var strideToCIADimension = map[types.STRIDE]string{
	types.InformationDisclosure: "confidentiality",
	types.Spoofing:              "integrity",
	types.Tampering:             "integrity",
	types.Repudiation:           "integrity",
	types.DenialOfService:       "availability",
}

func clampLikelihood(idx int) types.RiskExploitationLikelihood { return types.ClampLikelihood(idx) }

func clampImpact(idx int) types.RiskExploitationImpact { return types.ClampImpact(idx) }

// computeLikelihood nudges a rule's own baseline Likelihood by this specific asset's context: a
// -1/0/+1 delta from the asset's own RAA (+1 at or above raaLikelihoodThreshold, -1 below
// raaLikelihoodLowThreshold, 0 in between) plus +1 (never negative) if the asset is reachable from
// the internet -- either directly (the native Internet field, for the literal edge-facing
// gateway/ALB/WAF) or via the net:internet-reachable tag, an explicit, author-maintained signal
// for the real application/data asset sitting behind that already-modeled gateway, which itself
// correctly carries Internet: false. The two signals are deliberately ORed, not substituted for
// one another: Internet alone would miss exactly the backend-behind-the-gateway case the tag
// exists for, and that backend is usually the asset actually worth attacking, not the gateway
// itself. (An earlier version of this reachability signal computed it as a multi-hop walk from
// DMZ-tagged assets instead of reading an explicit tag; it was replaced after producing real false
// positives through shared infrastructure hops with multiple independent inbound paths -- see
// inject_risks.py's own history for compute_internet_reachable_ids().)
func computeLikelihood(baseline types.RiskExploitationLikelihood, technicalAsset *types.TechnicalAsset, steps ...int) types.RiskExploitationLikelihood {
	exposedDelta := 0
	if technicalAsset.Internet || contains(technicalAsset.Tags, "net:internet-reachable") {
		exposedDelta = 1
	}
	return types.AdjustLikelihood(baseline, technicalAsset.RAA, append([]int{exposedDelta}, steps...)...)
}

// computeImpact nudges a rule's own baseline Impact by this specific asset's context: a -1/0/+1
// delta from the asset's own rank on whichever single CIA dimension the finding's STRIDE category
// actually threatens (see strideToCIADimension). This used to also apply a gated +1 if the
// model's overall Business Criticality was Critical/Mission-Critical, mirroring
// inject_risks.py's compute_impact() -- removed from here for the same reason it was removed
// from the Python engine and every native script rule: it mostly inflated assets whose own CIA
// rating was genuinely lower than the system around them, not the under-rated components it was
// meant to protect, since every asset already carries an individually-justified CIA rating.
// Dead code as of this writing -- no built-in rule currently calls this helper (each computes
// Impact its own way; see the callers' own comments) -- but kept consistent with the other two
// layers regardless, so it's not a landmine if a future rule is ever wired into it.
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

// injectionImpact applies the symmetric CIA step for the higher of the processed confidentiality
// and integrity ranks. Injection both reads and alters what the asset handles, so a
// strictly-confidential but low-integrity asset is not rated down just because the category is
// filed under Tampering. Availability is left out: it is not what injection mainly threatens.
func injectionImpact(input *types.Model, baseline types.RiskExploitationImpact, asset *types.TechnicalAsset) types.RiskExploitationImpact {
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
