package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ServerSideRequestForgeryRule struct{}

func NewServerSideRequestForgeryRule() *ServerSideRequestForgeryRule {
	return &ServerSideRequestForgeryRule{}
}

func (*ServerSideRequestForgeryRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "server-side-request-forgery",
		Title: "Server-Side Request Forgery (SSRF)",
		Description: "When a server system (i.e. not a client) is accessing other server systems via typical web protocols " +
			"Server-Side Request Forgery (SSRF) or Local-File-Inclusion (LFI) or Remote-File-Inclusion (RFI) risks might arise. ",
		Impact:     "If this risk is unmitigated, attackers might be able to access sensitive services or files of network-reachable components by modifying outgoing calls of affected components.",
		ASVS:       "V12 - File and Resources Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action: "Remove caller control over outbound request destinations, or enforce a destination allowlist validated after " +
			"DNS resolution, and block egress to metadata endpoints and internal address ranges.",
		Mitigation: "Avoid building outbound URLs from caller input; map caller choices to server-side configured destinations. " +
			"Where a caller-supplied URL is unavoidable (webhooks, link previews, document fetch), allow only https and " +
			"allowlisted hosts, resolve DNS once, reject resolved addresses in loopback, link-local (169.254.0.0/16, " +
			"including the cloud metadata endpoint 169.254.169.254), RFC 1918, and IPv6 equivalents, and connect to that " +
			"validated address to defeat DNS rebinding. Disable automatic redirects or revalidate every hop, and disable " +
			"unused URL schemes in the HTTP client (file, gopher, dict, ftp). Route outbound traffic through an egress " +
			"proxy or firewall with a default-deny allowlist, require AWS IMDSv2 or the equivalent metadata protection, " +
			"and give the workload a least-privilege identity so any stolen metadata credentials grant little. Do not " +
			"return raw upstream responses or error detail to the caller. For third-party products, confirm the vendor's " +
			"SSRF protection and keep the product patched. References: CWE-918; CAPEC-664 (Server Side Request Forgery); " +
			"MITRE ATT&CK T1552.005 (Cloud Instance Metadata API); OWASP Top 10:2025 A01 (Broken Access Control); OWASP " +
			"API Security Top 10:2023 API7 (Server Side Request Forgery).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.InformationDisclosure,
		DetectionLogic: "In-scope non-client systems accessing (using outgoing communication links) targets with either HTTP or HTTPS protocol.",
		RiskAssessment: "The risk rating (low or medium) depends on the sensitivity of the data assets receivable via web protocols from " +
			"targets within the same network trust-boundary as well on the sensitivity of the data assets receivable via web protocols from the target asset itself. " +
			"Also for cloud-based environments the exploitation impact is at least medium, as cloud backend services can be attacked via SSRF.",
		FalsePositives: "Servers not sending outgoing web requests can be considered " +
			"as false positives after review.",
		ModelFailurePossibleReason: false,
		CWE:                        918,
	}
}

func (*ServerSideRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r *ServerSideRequestForgeryRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Technologies.GetAttribute(types.IsClient) || technicalAsset.Technologies.GetAttribute(types.LoadBalancer) {
			continue
		}
		for _, outgoingFlow := range technicalAsset.CommunicationLinks {
			if outgoingFlow.Protocol.IsPotentialWebAccessProtocol() {
				risks = append(risks, r.createRisk(input, technicalAsset, outgoingFlow))
			}
		}
	}
	return risks, nil
}

func (r *ServerSideRequestForgeryRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, outgoingFlow *types.CommunicationLink) *types.Risk {
	target := input.TechnicalAssets[outgoingFlow.TargetId]
	title := "<b>Server-Side Request Forgery (SSRF)</b> risk at <b>" + technicalAsset.Title + "</b> server-side web-requesting " +
		"the target <b>" + target.Title + "</b> via <b>" + outgoingFlow.Title + "</b>"
	impact := types.LowImpact
	// check by the target itself (can be in another trust-boundary)
	if input.HighestProcessedConfidentiality(target) == types.StrictlyConfidential {
		impact = types.MediumImpact
	}
	// check all potential attack targets within the same trust boundary (accessible via web protocols)
	uniqueDataBreachTechnicalAssetIDs := make(map[string]interface{})
	uniqueDataBreachTechnicalAssetIDs[technicalAsset.Id] = true
	for _, potentialTargetAsset := range input.TechnicalAssets {
		if !isSameTrustBoundaryNetworkOnly(input, technicalAsset, potentialTargetAsset.Id) {
			continue
		}
		for _, commLinkIncoming := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[potentialTargetAsset.Id] {
			if !commLinkIncoming.Protocol.IsPotentialWebAccessProtocol() {
				continue
			}
			uniqueDataBreachTechnicalAssetIDs[potentialTargetAsset.Id] = true
			if input.HighestProcessedConfidentiality(potentialTargetAsset) == types.StrictlyConfidential {
				impact = types.MediumImpact
			}
		}
	}
	// adjust for cloud-based special risks
	trustBoundaryId := input.GetTechnicalAssetTrustBoundaryId(technicalAsset)
	if impact == types.LowImpact && len(trustBoundaryId) > 0 && input.TrustBoundaries[input.GetTechnicalAssetTrustBoundaryId(technicalAsset)].Type.IsWithinCloud() {
		impact = types.MediumImpact
	}
	dataBreachTechnicalAssetIDs := make([]string, 0)
	for key := range uniqueDataBreachTechnicalAssetIDs {
		dataBreachTechnicalAssetIDs = append(dataBreachTechnicalAssetIDs, key)
	}
	likelihood := types.Likely
	if outgoingFlow.Usage == types.DevOps {
		likelihood = types.Unlikely
	}
	likelihood = computeLikelihood(likelihood, technicalAsset)
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: outgoingFlow.Id,
		DataBreachProbability:           types.Possible,
		DataBreachTechnicalAssetIDs:     dataBreachTechnicalAssetIDs,
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + target.Id + "@" + outgoingFlow.Id
	return risk
}
