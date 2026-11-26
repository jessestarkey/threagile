package builtin

import (
	"sort"

	"github.com/threagile/threagile/pkg/types"
)

type UnguardedAccessFromInternetRule struct{}

func NewUnguardedAccessFromInternetRule() *UnguardedAccessFromInternetRule {
	return &UnguardedAccessFromInternetRule{}
}

func (*UnguardedAccessFromInternetRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unguarded-access-from-internet",
		Title: "Unguarded Access From Internet",
		Description: "Internet-exposed assets must be guarded by a protecting service, application, " +
			"or reverse-proxy.",
		Impact: "If this risk is unmitigated, attackers might be able to directly attack sensitive systems without any hardening components in-between " +
			"due to them being directly exposed on the internet.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action: "Remove direct internet reachability from this asset and route all inbound traffic through a reverse proxy, " +
			"API gateway, or WAF in a DMZ, with administrative access only through a bastion or VPN.",
		Mitigation: "Remove public IP addresses and endpoints from this asset, and place it in a private subnet.\n" +
			"Expose only the paths that must be public through a guarding component (an application gateway or load balancer with WAF, an API gateway, or a hardened reverse proxy) that terminates TLS, filters requests, and rate-limits.\n" +
			"Restrict the asset's inbound rules to that component's subnet.\n" +
			"Route administrative access (SSH, RDP, and management consoles) through a bastion or zero-trust access broker with MFA and session logging, never through a public port.\n" +
			"For file exchange, use a store-and-forward transfer host in the DMZ instead of exposing internal file servers.\n" +
			"Scan the external attack surface regularly to confirm nothing else is exposed, and for DoD systems, follow the DISA SCCA boundary architecture.",
		Check:        "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:     types.Architecture,
		STRIDE:       types.ElevationOfPrivilege,
		FindingClass: types.FindingClassWeaknessShown,
		DetectionLogic: "In-scope technical assets (excluding " + types.LoadBalancer + ") with confidentiality rating " +
			"of " + types.Confidential.String() + " (or higher) or with integrity rating of " + types.Critical.String() + " (or higher) when " +
			"accessed directly from the internet, meaning by an internet-facing external entity or out-of-scope asset " +
			"(an in-scope internet-facing component such as a gateway or firewall calling inward is the guarded path, not internet access). All " +
			types.WebServer + ", " + types.WebApplication + ", " + types.ReverseProxy + ", " + types.WAF + ", and " + types.Gateway + " assets are exempted from this risk when " +
			"they do not consist of custom developed code and " +
			"the data-flow only consists of HTTP or FTP protocols. Access from " + types.Monitoring + " systems " +
			"as well as VPN-protected connections are exempted.",
		RiskAssessment:             "Likelihood starts at Likely. Impact starts at Low and steps on the highest of the asset's own confidentiality, integrity and availability ratings. Each step is one level: impact up for a rating of confidential/critical or above, down for internal/operational or below; likelihood also moves with the asset's attractiveness (RAA) and internet exposure.",
		FalsePositives:             "When other means of filtering client requests are applied equivalent of " + types.ReverseProxy + ", " + types.WAF + ", or " + types.Gateway + " components.",
		ModelFailurePossibleReason: false,
		CWE:                        501,
	}
}

func (*UnguardedAccessFromInternetRule) SupportedTags() []string {
	return []string{}
}

func (r *UnguardedAccessFromInternetRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}

		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		sort.Sort(types.ByTechnicalCommunicationLinkIdSort(commLinks))
		for _, incomingAccess := range commLinks {
			if technicalAsset.Technologies.GetAttribute(types.LoadBalancer) {
				continue
			}
			if !technicalAsset.CustomDevelopedParts &&
				((technicalAsset.Technologies.GetAttribute(types.IsHTTPInternetAccessOK) && (incomingAccess.Protocol == types.HTTP || incomingAccess.Protocol == types.HTTPS)) ||
					(technicalAsset.Technologies.GetAttribute(types.IsFTPInternetAccessOK) && (incomingAccess.Protocol == types.FTP || incomingAccess.Protocol == types.FTPS || incomingAccess.Protocol == types.SFTP))) {
				continue
			}
			if input.TechnicalAssets[incomingAccess.SourceId].Technologies.GetAttribute(types.Monitoring) ||
				incomingAccess.VPN {
				continue
			}
			if technicalAsset.Confidentiality < types.Confidential && technicalAsset.Integrity < types.Critical {
				continue
			}
			// The caller must be on the internet side: an internet-facing external entity or
			// out-of-scope asset. An in-scope internet-facing component (an application gateway, a
			// firewall) calling inward is the guarded path, and its log forwarding or egress traffic
			// is not internet access to the target.
			source := input.TechnicalAssets[incomingAccess.SourceId]
			if !source.Internet || (!source.OutOfScope && source.Type != types.ExternalEntity) {
				continue
			}

			risks = append(risks, r.createRisk(technicalAsset, incomingAccess, source))
		}
	}
	return risks, nil
}

func (r *UnguardedAccessFromInternetRule) createRisk(dataStore *types.TechnicalAsset, dataFlow *types.CommunicationLink,
	clientFromInternet *types.TechnicalAsset) *types.Risk {
	// RAA affects how likely exploitation is, not how severe it is, so it enters through
	// computeLikelihood(), and Impact follows the asset's own CIA rating.
	//
	// The checks in GenerateRisks() decide whether the risk applies at all, from the caller's
	// side. computeLikelihood() reads the data store's own exposure, which can differ.
	impact := computeImpact(types.LowImpact, r.Category().STRIDE, dataStore)
	// The GenerateRisks() check that the caller (clientFromInternet) itself carries
	// Internet: true is kept as-is -- that's the detection-logic question of whether this risk
	// applies at all (is this genuinely internet-originated traffic), separate from the
	// Likelihood/Impact scoring below. computeLikelihood() separately checks dataStore's own
	// reachability signals, which can differ from the caller's.
	likelihood := computeLikelihood(types.Likely, dataStore)
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood: likelihood,
		ExploitationImpact:     impact,
		Title: "<b>Unguarded Access from Internet</b> of <b>" + dataStore.Title + "</b> by <b>" +
			clientFromInternet.Title + "</b>" + " via <b>" + dataFlow.Title + "</b>",
		MostRelevantTechnicalAssetId:    dataStore.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     []string{dataStore.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + dataStore.Id + "@" + clientFromInternet.Id + "@" + dataFlow.Id
	return risk
}
