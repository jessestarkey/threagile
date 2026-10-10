package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type UntrustedDeserializationRule struct{}

func NewUntrustedDeserializationRule() *UntrustedDeserializationRule {
	return &UntrustedDeserializationRule{}
}

func (*UntrustedDeserializationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "untrusted-deserialization",
		Title: "Untrusted Deserialization",
		Description: "When a technical asset accepts data in a specific serialized form (like Java or .NET serialization), " +
			"Untrusted Deserialization risks might arise." +
			"<br><br>See <a href=\"https://christian-schneider.net/JavaDeserializationSecurityFAQ.html\">https://christian-schneider.net/JavaDeserializationSecurityFAQ.html</a> " +
			"for more details.",
		Impact:     "If this risk is unmitigated, attackers might be able to execute code on target systems by exploiting untrusted deserialization endpoints.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
		Action: "Stop deserializing untrusted input with native object serializers; switch to data-only formats with schema " +
			"validation, and enforce strict type allowlists where native deserialization must remain.",
		Mitigation: "Replace native object serialization on every externally reachable interface (Java ObjectInputStream, RMI, JMX " +
			"and EJB remoting, .NET BinaryFormatter, NetDataContractSerializer, LosFormatter and ViewState without MAC " +
			"validation, Python pickle, PHP unserialize, Ruby Marshal, and YAML loaders that construct arbitrary objects) " +
			"with data-only formats such as JSON or Protocol Buffers bound to explicit DTO types and validated against a " +
			"schema. Where native deserialization cannot be removed, apply a strict allowlist of permitted classes (Java " +
			"JEP 290 serialization filters via jdk.serialFilter, a restrictive .NET SerializationBinder), verify an HMAC " +
			"over the payload before deserializing it, and disable polymorphic type handling in JSON libraries (Jackson " +
			"default typing, Json.NET TypeNameHandling other than None). Remove unused gadget-chain libraries from the " +
			"classpath and keep dependencies patched. Run the deserializing process with least privilege and restricted " +
			"egress to limit the impact of code execution. For third-party products, confirm the vendor has removed or " +
			"filtered unsafe deserialization and keep the product patched. References: CWE-502; CAPEC-586 (Object " +
			"Injection); MITRE ATT&CK T1190; OWASP Top 10:2025 A08 (Software or Data Integrity Failures).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope technical assets accepting serialization data formats (including EJB and RMI protocols).",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) data deserialized can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        502,
	}
}

func (*UntrustedDeserializationRule) SupportedTags() []string {
	return []string{}
}

func (r *UntrustedDeserializationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		hasOne, acrossTrustBoundary := false, false
		commLinkTitle := ""
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.Serialization {
				hasOne = true
			}
		}
		if technicalAsset.Technologies.GetAttribute(types.EJB) {
			hasOne = true
		}
		// check for any incoming IIOP and JRMP protocols
		for _, commLink := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			if commLink.Protocol == types.IIOP || commLink.Protocol == types.IiopEncrypted ||
				commLink.Protocol == types.JRMP || commLink.Protocol == types.JrmpEncrypted {
				hasOne = true
				if isAcrossTrustBoundaryNetworkOnly(input, commLink) {
					acrossTrustBoundary = true
					commLinkTitle = commLink.Title
				}
			}
		}
		if hasOne {
			risks = append(risks, r.createRisk(input, technicalAsset, acrossTrustBoundary, commLinkTitle))
		}
	}
	return risks, nil
}

func (r *UntrustedDeserializationRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset, acrossTrustBoundary bool, commLinkTitle string) *types.Risk {
	title := "<b>Untrusted Deserialization</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Impact intentionally stays keyed off all three CIA dimensions rather than narrowing to
	// just Integrity (this category's own STRIDE value): per this category's own Impact text,
	// untrusted deserialization lets an attacker "execute code on target systems" -- full
	// remote code execution threatens any of the three dimensions, not just tampering.
	impact := types.HighImpact
	likelihood := types.Likely
	if acrossTrustBoundary {
		likelihood = types.VeryLikely
		title += " across a trust boundary (at least via communication link <b>" + commLinkTitle + "</b>)"
	}
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.VeryHighImpact
	}
	likelihood = computeLikelihood(likelihood, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
