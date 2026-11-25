package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ServiceRegistryPoisoningRule struct{}

func NewServiceRegistryPoisoningRule() *ServiceRegistryPoisoningRule {
	return &ServiceRegistryPoisoningRule{}
}

func (*ServiceRegistryPoisoningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "service-registry-poisoning",
		Title:       "Service Registry Poisoning",
		Description: "When a service registry used for discovery of trusted service endpoints Service Registry Poisoning risks might arise.",
		Impact: "If this risk remains unmitigated, attackers might be able to poison the service registry with malicious service endpoints or " +
			"malicious lookup and config data leading to breach of sensitive data.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action: "Require authenticated, ACL-restricted writes to the service registry, and verify every discovered endpoint's " +
			"identity with mutual TLS before trusting it.",
		Mitigation: "Enable the registry's access control with default deny (Consul ACLs, etcd RBAC, or Kubernetes RBAC on Services and EndpointSlices), so each service can change only its own entries and only operators can change configuration.\n" +
			"Encrypt and mutually authenticate all registry traffic, including gossip.\n" +
			"Do not treat a registry lookup as proof of identity. Callers verify each discovered endpoint over mutual TLS against a service identity (a SPIFFE ID or certificate SAN), which a service mesh enforces automatically.\n" +
			"Restrict network access to the registry API, audit all writes, and alert on registrations from unexpected sources or for unexpected service names.\n" +
			"Keep secrets out of the registry's key-value store.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Spoofing,
		FindingClass:   types.FindingClassControlNotEvidenced,
		DetectionLogic: "In-scope service registries.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical assets accessing the service registry " +
			"as well as the data assets processed.",
		FalsePositives: "Service registries not used for service discovery " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        693,
	}
}

func (*ServiceRegistryPoisoningRule) SupportedTags() []string {
	return []string{}
}

func (r *ServiceRegistryPoisoningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technologies.GetAttribute(types.ServiceRegistry) {
			incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			risks = append(risks, r.createRisk(input, technicalAsset, incomingFlows))
		}
	}
	return risks, nil
}

func (r *ServiceRegistryPoisoningRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlows []*types.CommunicationLink) *types.Risk {
	title := "<b>Service Registry Poisoning</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact: baseline plus the CIA step on the dimension the STRIDE category threatens, for the
	// highest rank across the registry, its callers and the data on their links.
	rank := processedRank(input, r.Category().STRIDE, technicalAsset)
	for _, incomingFlow := range incomingFlows {
		rank = max(rank, processedRank(input, r.Category().STRIDE, input.TechnicalAssets[incomingFlow.SourceId]),
			linkRank(input, r.Category().STRIDE, incomingFlow))
	}
	impact := types.AdjustImpactForRank(types.MediumImpact, rank)

	likelihood := computeLikelihood(types.Unlikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id}, // TODO: find all service-lookup-using tech assets, which then might use spoofed lookups?
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
