package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingWafRule struct{}

func NewMissingWafRule() *MissingWafRule {
	return &MissingWafRule{}
}

func (*MissingWafRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-waf",
		Title: "Missing Web Application Firewall (WAF)",
		Description: "To have a first line of filtering defense, security architectures with web-services or web-applications should include a WAF in front of them. " +
			"Even though a WAF is not a replacement for security (all components must be secure even without a WAF) it adds another layer of defense to the overall " +
			"system by delaying some attacks and having easier attack alerting through it.",
		Impact:     "If this risk is unmitigated, attackers might be able to apply standard attack pattern tests at great speed without any filtering.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html",
		Action: "Route all traffic to this web application or API through a WAF running the OWASP Core Rule Set or provider " +
			"managed rules in prevention mode, and lock the origin to accept traffic only from the WAF.",
		Mitigation: "Place a web application firewall in front of this asset (Azure Application Gateway WAF or Front Door WAF, AWS " +
			"WAF, or ModSecurity or Coraza with the OWASP Core Rule Set on the reverse proxy) and make it the only network " +
			"path to the application by restricting the origin to the WAF (private endpoint, access restriction to the " +
			"gateway subnet, or an origin-verification header). Start in detection mode to tune false positives, then " +
			"switch to prevention mode with a documented paranoia level and exclusion list. Enable rate-based rules, bot " +
			"management, IP reputation filtering as appropriate, and request body size limits. Use the WAF for virtual " +
			"patching of newly disclosed vulnerabilities while code fixes ship. Forward WAF logs to the SIEM and alert on " +
			"spikes in blocked requests and on rule hits against sensitive endpoints. Treat the WAF as defense in depth " +
			"only; it does not replace input validation and output encoding in the application. References: CWE-693; MITRE " +
			"ATT&CK T1190, T1595.002 (Vulnerability Scanning); NIST SP 800-53 SC-7, SI-4.",
		Check:          "GetAttribute a Web Application Firewall (WAF) in place?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web-services and/or web-applications accessed across a network trust boundary not having a Web Application Firewall (WAF) in front of them.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Targets only accessible via WAFs or reverse proxies containing a WAF component (like ModSecurity) can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (*MissingWafRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingWafRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		if !technicalAsset.Technologies.GetAttribute(types.WebApplication) &&
			!technicalAsset.Technologies.GetAttribute(types.IsWebService) {
			continue
		}
		for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			if isAcrossTrustBoundaryNetworkOnly(input, incomingAccess) &&
				incomingAccess.Protocol.IsPotentialWebAccessProtocol() &&
				!input.TechnicalAssets[incomingAccess.SourceId].Technologies.GetAttribute(types.WAF) {
				risks = append(risks, r.createRisk(input, technicalAsset))
				break
			}
		}
	}
	return risks, nil
}

func (r *MissingWafRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>" + technicalAsset.Title + "</b>"
	likelihood := computeLikelihood(types.Unlikely, technicalAsset)
	// Impact intentionally stays keyed off all three CIA dimensions rather than narrowing to
	// just Integrity (this category's own STRIDE value): a missing WAF removes a general
	// filtering layer against "standard attack pattern tests," not a dimension-specific one --
	// it's as relevant to a confidentiality- or availability-driven attack as a tampering one.
	impact := types.LowImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		input.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
