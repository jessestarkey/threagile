package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type LdapInjectionRule struct{}

func NewLdapInjectionRule() *LdapInjectionRule {
	return &LdapInjectionRule{}
}

func (*LdapInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "ldap-injection",
		Title: "LDAP-Injection",
		Description: "When an LDAP server is accessed LDAP-Injection risks might arise. " +
			"The risk rating depends on the sensitivity of the LDAP server itself and of the data assets processed.",
		Impact:     "If this risk remains unmitigated, attackers might be able to modify LDAP queries and access more data from the LDAP server than allowed.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
		Action: "Escape all caller-controlled input with RFC 4515 filter encoding and RFC 4514 DN encoding before it reaches " +
			"an LDAP query, and bind with a least-privilege read-only service account.",
		Mitigation: "Never concatenate caller-supplied values into LDAP search filters or distinguished names. Use the directory " +
			"library's escaping functions (Spring LDAP LdapEncoder, Python ldap3 escape_filter_chars, the OWASP Java " +
			"Encoder or ESAPI equivalents) to encode the filter metacharacters asterisk, parentheses, backslash, and NUL " +
			"per RFC 4515 and DN special characters per RFC 4514, or use a filter builder that treats values as data. " +
			"Validate inputs such as usernames against a strict allowlist pattern first. Bind with a dedicated service " +
			"account that can read only the attributes and subtrees the application needs, never a directory " +
			"administrator, and disable anonymous binds. Reject empty passwords before a simple bind, since many " +
			"directories treat an empty-password bind as an unauthenticated success. Use LDAPS or StartTLS with " +
			"certificate validation, and log failed and anomalous queries. For third-party products, confirm the vendor " +
			"encodes LDAP input and keep the product patched. References: CWE-90; CAPEC-136 (LDAP Injection); OWASP Top " +
			"10:2025 A05 (Injection).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope clients accessing LDAP servers via typical LDAP access protocols.",
		RiskAssessment: "The risk rating depends on the sensitivity of the LDAP server itself and of the data assets processed.",
		FalsePositives: "LDAP server queries by search values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        90,
	}
}

func (*LdapInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *LdapInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if r.skipAsset(input, incomingFlow) {
				continue
			}
			if incomingFlow.Protocol == types.LDAP || incomingFlow.Protocol == types.LDAPS {
				likelihood := types.Likely
				if incomingFlow.Usage == types.DevOps {
					likelihood = types.Unlikely
				}
				risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow, likelihood))
			}
		}
	}
	return risks, nil
}

func (li *LdapInjectionRule) skipAsset(input *types.Model, incomingFlow *types.CommunicationLink) bool {
	return input.TechnicalAssets[incomingFlow.SourceId].OutOfScope
}

func (r *LdapInjectionRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink, likelihood types.RiskExploitationLikelihood) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>LDAP-Injection</b> risk at <b>" + caller.Title + "</b> against LDAP server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	// Impact intentionally stays keyed off both Confidentiality and Integrity rather than
	// narrowing to just Integrity (this category's own STRIDE value): per this category's own
	// Impact text, LDAP injection lets an attacker "modify LDAP queries and access more data" --
	// both a tampering and an information-disclosure consequence.
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood = computeLikelihood(likelihood, technicalAsset)
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
