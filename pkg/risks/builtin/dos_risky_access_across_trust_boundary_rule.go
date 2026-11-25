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
		Mitigation: "Enforce per-client and global rate limits, concurrency caps, request-size limits, timeouts, and pagination limits at the gateway in front of this asset, returning HTTP 429 instead of queuing unbounded work.\n" +
			"Bound expensive operations (search, report generation, file processing, regular expressions, and GraphQL depth) with resource budgets, and move long-running work to queues with backpressure.\n" +
			"Restrict administrative and maintenance flows to a VPN, private endpoint, or IP-allowlisted management network.\n" +
			"Deploy the asset across availability zones behind a health-checked load balancer, and use circuit breakers in callers so one saturated dependency does not cascade.\n" +
			"Put internet-facing entry points behind the provider's DDoS protection and WAF rate-based rules.\n" +
			"Load-test against the documented availability objective to confirm the limits hold.",
		Check:        "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:     types.Operations,
		STRIDE:       types.DenialOfService,
		FindingClass: types.FindingClassWeaknessShown,
		DetectionLogic: "In-scope technical assets (excluding " + types.LoadBalancer + ") with " +
			"availability rating of " + types.Critical.String() + " or higher which have incoming data-flows across a " +
			"network trust-boundary (excluding " + types.DevOps.String() + " usage).",
		RiskAssessment:             "Likelihood starts at Possible. Impact starts at Low and steps on the asset's availability; the rule fires only at critical availability or above, so it lands at Medium, one level lower when the link is VPN-protected or IP-filtered or the asset is redundant. Each step is one level: impact up for a rating of confidential/critical or above, down for internal/operational or below; likelihood also moves with the asset's attractiveness (RAA) and internet exposure.",
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

	mitigated := incomingAccess.VPN || incomingAccess.IpFiltered || technicalAsset.Redundant
	risks = append(risks, r.createRisk(technicalAsset, incomingAccess, linkId, hopBetween, input.TechnicalAssets[incomingAccess.SourceId], mitigated))
	return risks
}

func (r *DosRiskyAccessAcrossTrustBoundaryRule) createRisk(techAsset *types.TechnicalAsset, dataFlow *types.CommunicationLink, linkId string, hopBetween string,
	clientOutsideTrustBoundary *types.TechnicalAsset, mitigated bool) *types.Risk {
	// Low baseline plus the availability step, and one level lower when the link is VPN-protected
	// or IP-filtered or the target is redundant, the mitigations the model can show.
	impact := types.ClampImpact(int(computeImpact(types.LowImpact, r.Category().STRIDE, techAsset)) + stepIf(mitigated, -1))
	if len(hopBetween) > 0 {
		hopBetween = " forwarded via <b>" + hopBetween + "</b>"
	}
	likelihood := computeLikelihood(types.PossibleLikelihood, techAsset)
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
