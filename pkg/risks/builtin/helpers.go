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
const raaLikelihoodThreshold = 40.0
const raaLikelihoodLowThreshold = 15.0

// ciaRankToDelta maps a CIA rank (Confidentiality's and Criticality's shared 0-4 ordinal shape --
// Criticality covers both Integrity and Availability) to the -1/0/+1 Impact delta applied on top
// of a baseline. Mirrors CIA_RANK_TO_DELTA in inject_risks.py: the bottom two tiers pull the
// baseline down a notch, the middle tier leaves it alone, the top two tiers push it up a notch.
var ciaRankToDelta = [...]int{-1, -1, 0, 1, 1}

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

func clampLikelihood(idx int) types.RiskExploitationLikelihood {
	if idx < 0 {
		idx = 0
	} else if idx > 3 {
		idx = 3
	}
	return types.RiskExploitationLikelihood(idx)
}

func clampImpact(idx int) types.RiskExploitationImpact {
	if idx < 0 {
		idx = 0
	} else if idx > 3 {
		idx = 3
	}
	return types.RiskExploitationImpact(idx)
}

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
func computeLikelihood(baseline types.RiskExploitationLikelihood, technicalAsset *types.TechnicalAsset) types.RiskExploitationLikelihood {
	raaDelta := 0
	if technicalAsset.RAA >= raaLikelihoodThreshold {
		raaDelta = 1
	} else if technicalAsset.RAA < raaLikelihoodLowThreshold {
		raaDelta = -1
	}
	exposedDelta := 0
	if technicalAsset.Internet || contains(technicalAsset.Tags, "net:internet-reachable") {
		exposedDelta = 1
	}
	return clampLikelihood(int(baseline) + raaDelta + exposedDelta)
}

// computeImpact nudges a rule's own baseline Impact by this specific asset's context: a -1/0/+1
// delta from the asset's own rank on whichever single CIA dimension the finding's STRIDE category
// actually threatens (see strideToCIADimension), plus a gated +1 if the model's overall Business
// Criticality is Critical or Mission-Critical -- but only when this asset's own CIA-driven delta
// hasn't already earned that +1, to avoid double-counting the same underlying fact (a Critical/
// Mission-Critical system is almost by definition built from high-CIA components).
func computeImpact(baseline types.RiskExploitationImpact, stride types.STRIDE, technicalAsset *types.TechnicalAsset, model *types.Model) types.RiskExploitationImpact {
	rank := int(technicalAsset.Confidentiality)
	if int(technicalAsset.Integrity) > rank {
		rank = int(technicalAsset.Integrity)
	}
	if int(technicalAsset.Availability) > rank {
		rank = int(technicalAsset.Availability)
	}
	if dimension, ok := strideToCIADimension[stride]; ok {
		switch dimension {
		case "confidentiality":
			rank = int(technicalAsset.Confidentiality)
		case "integrity":
			rank = int(technicalAsset.Integrity)
		case "availability":
			rank = int(technicalAsset.Availability)
		}
	}
	ciaDelta := ciaRankToDelta[rank]
	criticalityDelta := 0
	missionCriticalSystem := model.BusinessCriticality == types.Critical || model.BusinessCriticality == types.MissionCritical
	if missionCriticalSystem && ciaDelta < 1 {
		criticalityDelta = 1
	}
	return clampImpact(int(baseline) + ciaDelta + criticalityDelta)
}
