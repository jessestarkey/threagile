package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type DosRiskyAccessAcrossTrustBoundaryRule struct{}

func NewDosRiskyAccessAcrossTrustBoundaryRule() *DosRiskyAccessAcrossTrustBoundaryRule {
	return &DosRiskyAccessAcrossTrustBoundaryRule{}
}

func (*DosRiskyAccessAcrossTrustBoundaryRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "dos-risky-access-across-trust-boundary",
		Title: "DoS-risky Access Across Trust-Boundary",
		Description: "Assets accessed across trust boundaries with critical or mission-critical availability rating " +
			"are more prone to Denial-of-Service (DoS) risks.",
		Impact:     "If this risk remains unmitigated, attackers might be able to disturb the availability of important parts of the system.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
		Action: "Rate-limit and quota every cross-boundary entry point to this availability-critical asset, move maintenance " +
			"access behind VPN or IP filtering, and deploy the asset redundantly.",
		Mitigation: "Enforce per-client and global rate limits, concurrency caps, request-size limits, timeouts, and pagination " +
			"limits at the API gateway or ingress in front of this asset, returning HTTP 429 instead of queuing unbounded " +
			"work. Bound expensive operations (search, report generation, file processing, regular expressions, GraphQL " +
			"depth and cost) with explicit resource budgets, and move long-running work to asynchronous queues with " +
			"backpressure. Restrict administrative and maintenance data flows to a VPN, private endpoint, or " +
			"IP-allowlisted management network. Deploy the asset redundantly across availability zones behind a " +
			"health-checked load balancer with bounded autoscaling, and use circuit breakers and bulkheads in callers so " +
			"one saturated dependency does not cascade. Put internet-facing entry points behind the provider's DDoS " +
			"protection (Azure DDoS Protection, AWS Shield Advanced) and WAF rate-based rules. Load-test against the " +
			"documented availability objective to confirm the limits hold. References: CWE-400, CWE-770; CAPEC-125 " +
			"(Flooding); MITRE ATT&CK T1498 (Network Denial of Service), T1499 (Endpoint Denial of Service); OWASP API " +
			"Security Top 10:2023 API4 (Unrestricted Resource Consumption); NIST SP 800-53 SC-5.",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Operations,
		STRIDE:   types.DenialOfService,
		DetectionLogic: "In-scope technical assets (excluding " + types.LoadBalancer + ") with " +
			"availability rating of " + types.Critical.String() + " or higher which have incoming data-flows across a " +
			"network trust-boundary (excluding " + types.DevOps.String() + " usage).",
		RiskAssessment: "Matching technical assets with availability rating " +
			"of " + types.Critical.String() + " or higher are " +
			"at " + types.LowSeverity.String() + " risk. When the availability rating is " +
			types.MissionCritical.String() + " and neither a VPN nor IP filter for the incoming data-flow nor redundancy " +
			"for the asset is applied, the risk-rating is considered " + types.MediumSeverity.String() + ".", // TODO reduce also, when data-flow authenticated and encrypted?
		FalsePositives:             "When the accessed target operations are not time- or resource-consuming.",
		ModelFailurePossibleReason: false,
		CWE:                        400,
	}
}

func (*DosRiskyAccessAcrossTrustBoundaryRule) SupportedTags() []string {
	return []string{}
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]

		if r.skipAsset(technicalAsset) {
			continue
		}

		for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			sourceAsset := input.TechnicalAssets[incomingAccess.SourceId]
			if sourceAsset.Technologies.GetAttribute(types.IsTrafficForwarding) {
				// Now try to walk a call chain up (1 hop only) to find a caller's caller used by human
				callersCommLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[sourceAsset.Id]
				for _, callersCommLink := range callersCommLinks {
					risks = r.potentiallyAddRisk(input, technicalAsset, callersCommLink, incomingAccess.Id, sourceAsset.Title, risks)
				}
			} else {
				risks = r.potentiallyAddRisk(input, technicalAsset, incomingAccess, "", "", risks)
			}
		}
	}
	return risks, nil
}

func (asl DosRiskyAccessAcrossTrustBoundaryRule) skipAsset(techAsset *types.TechnicalAsset) bool {
	return techAsset.OutOfScope || !techAsset.Technologies.GetAttribute(types.LoadBalancer) &&
		techAsset.Availability < types.Critical
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) potentiallyAddRisk(
	input *types.Model, technicalAsset *types.TechnicalAsset, incomingAccess *types.CommunicationLink,
	linkId string, hopBetween string, risks []*types.Risk) []*types.Risk {

	if !isAcrossTrustBoundaryNetworkOnly(input, incomingAccess) {
		return risks
	}
	if incomingAccess.Usage == types.DevOps {
		return risks
	}
	if incomingAccess.Protocol.IsProcessLocal() {
		return risks
	}

	highRisk := technicalAsset.Availability == types.MissionCritical && !incomingAccess.VPN && !incomingAccess.IpFiltered && !technicalAsset.Redundant
	risks = append(risks, r.createRisk(technicalAsset, incomingAccess, linkId, hopBetween, input.TechnicalAssets[incomingAccess.SourceId], highRisk))
	return risks
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) createRisk(techAsset *types.TechnicalAsset, dataFlow *types.CommunicationLink, linkId string, hopBetween string,
	clientOutsideTrustBoundary *types.TechnicalAsset, moreRisky bool) *types.Risk {
	// Already single-dimension (Availability, matching this category's STRIDE value) and
	// asset-scoped, but not reused via the shared computeImpact() helper: moreRisky folds in
	// rule-specific mitigating factors (VPN, IP filtering, redundancy) the generic helper has no
	// way to know about, not just the asset's own Availability rank.
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	if len(hopBetween) > 0 {
		hopBetween = " forwarded via <b>" + hopBetween + "</b>"
	}
	likelihood := computeLikelihood(types.Unlikely, techAsset)
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Denial-of-Service</b> risky access of <b>" + techAsset.Title + "</b> by <b>" + clientOutsideTrustBoundary.Title +
			"</b> via <b>" + dataFlow.Title + "</b>" + hopBetween,
		MostRelevantTechnicalAssetId:    techAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + techAsset.Id + "@" + clientOutsideTrustBoundary.Id + "@" + dataFlow.Id
	if dataFlow.Id != linkId {
		risk.SyntheticId += "->" + linkId
	}

	return risk
}
