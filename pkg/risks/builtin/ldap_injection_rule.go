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
		Mitigation: "Never concatenate caller-supplied values into LDAP filters or distinguished names. Encode them with the library's escaping functions (such as Spring LdapEncoder or ldap3 escape_filter_chars), or use a filter builder that treats values as data.\n" +
			"Validate inputs such as usernames against a strict allowlist pattern first.\n" +
			"Bind with a service account that reads only the attributes and subtrees the application needs, never a directory administrator, and disable anonymous binds.\n" +
			"Reject empty passwords before a simple bind, since many directories treat an empty-password bind as an unauthenticated success.\n" +
			"Use LDAPS or StartTLS with certificate validation, and log failed and anomalous queries.\n" +
			"For third-party products, confirm the vendor encodes LDAP input, and keep the product patched.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		FindingClass:   types.FindingClassControlNotEvidenced,
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
				likelihood := computeLikelihood(types.PossibleLikelihood, technicalAsset, devOpsStep(incomingFlow))
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
	// Impact: baseline plus the CIA step on the higher of the processed confidentiality and integrity
	// (readAndAlterImpact): injection both reads and alters data.
	impact := readAndAlterImpact(input, types.MediumImpact, technicalAsset)
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
