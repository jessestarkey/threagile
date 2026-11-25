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
		Action:     "Stop deserializing untrusted input with native object serializers. Instead, use data-only formats with schema validation, and enforce strict type allowlists where native deserialization must remain.",
		Mitigation: "Replace native object serialization on every externally reachable interface (Java ObjectInputStream and RMI, .NET BinaryFormatter and unvalidated ViewState, Python pickle, PHP unserialize, Ruby Marshal, and unsafe YAML loaders) with JSON or Protocol Buffers bound to explicit DTO types and validated against a schema.\n" +
			"Where native deserialization must remain, allow only permitted classes (Java serialization filters or a restrictive .NET SerializationBinder), verify an HMAC over the payload before deserializing it, and disable polymorphic typing in JSON libraries (Jackson default typing or Json.NET TypeNameHandling).\n" +
			"Remove unused gadget-chain libraries, and keep dependencies patched.\n" +
			"Run the deserializing process with least privilege and restricted egress to limit the impact of code execution.\n" +
			"For third-party products, confirm the vendor has removed or filtered unsafe deserialization, and keep the product patched.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Architecture,
		STRIDE:         types.Tampering,
		FindingClass:   types.FindingClassControlNotEvidenced,
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
	// Impact: baseline plus the CIA step on the higher of the processed confidentiality and integrity
	// (readAndAlterImpact): deserialization leads to code execution, which both reads and alters data.
	impact := readAndAlterImpact(parsedModel, types.HighImpact, technicalAsset)
	if acrossTrustBoundary {
		title += " across a trust boundary (at least via communication link <b>" + commLinkTitle + "</b>)"
	}
	// One level more likely when the serialized input arrives across a trust boundary.
	likelihood := computeLikelihood(types.PossibleLikelihood, technicalAsset, stepIf(acrossTrustBoundary, 1))
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
