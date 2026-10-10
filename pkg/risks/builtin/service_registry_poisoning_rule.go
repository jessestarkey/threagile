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
		Mitigation: "Enable the registry's access control with default deny (Consul ACLs, etcd client-certificate authentication " +
			"and RBAC, Eureka behind authenticated endpoints, Kubernetes RBAC on Services, Endpoints, and EndpointSlices) " +
			"so each service can register and deregister only its own entries and only operators can change configuration " +
			"keys. Encrypt and mutually authenticate all registry traffic, including gossip. Do not treat a registry " +
			"lookup as proof of identity: callers must verify the discovered endpoint over mutual TLS against a service " +
			"identity (SPIFFE ID or certificate SAN) issued by the internal CA, which a service mesh (Istio, Linkerd, " +
			"Consul service mesh) enforces automatically. Restrict network access to the registry API to the cluster or " +
			"service subnet, audit all write operations, and alert on registrations from unexpected sources or for " +
			"unexpected service names. Keep secrets out of the registry's key-value store. References: CWE-923, CWE-345; " +
			"MITRE ATT&CK T1557 (Adversary-in-the-Middle); NIST SP 800-53 SC-23, AC-3; NIST SP 800-204A.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Spoofing,
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
	// Impact intentionally stays keyed off all three CIA dimensions, across the registry, its
	// callers, and the link between them, rather than narrowing to just Integrity (this
	// category's own STRIDE value): per this category's own Impact text, poisoned lookup data
	// can lead to "breach of sensitive data" downstream just as much as a direct tampering
	// consequence at the registry itself.
	impact := types.LowImpact

	for _, incomingFlow := range incomingFlows {
		caller := input.TechnicalAssets[incomingFlow.SourceId]
		if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical || input.HighestProcessedAvailability(technicalAsset) == types.MissionCritical ||
			input.HighestProcessedConfidentiality(caller) == types.StrictlyConfidential || input.HighestProcessedIntegrity(caller) == types.MissionCritical || input.HighestProcessedAvailability(caller) == types.MissionCritical ||
			input.HighestCommunicationLinkConfidentiality(incomingFlow) == types.StrictlyConfidential || input.HighestCommunicationLinkIntegrity(incomingFlow) == types.MissionCritical || input.HighestCommunicationLinkAvailability(incomingFlow) == types.MissionCritical {
			impact = types.MediumImpact
			break
		}
	}

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
