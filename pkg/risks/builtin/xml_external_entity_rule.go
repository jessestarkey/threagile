package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type XmlExternalEntityRule struct{}

func NewXmlExternalEntityRule() *XmlExternalEntityRule {
	return &XmlExternalEntityRule{}
}

func (*XmlExternalEntityRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "xml-external-entity",
		Title:       "XML External Entity (XXE)",
		Description: "When a technical asset accepts data in XML format, XML External Entity (XXE) risks might arise.",
		Impact: "If this risk is unmitigated, attackers might be able to read sensitive files (configuration data, key/credential files, deployment files, " +
			"business data files, etc.) form the filesystem of affected components and/or access sensitive services or files " +
			"of other components.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
		Action: "Disable DTD processing and external entity resolution in every XML parser that handles caller-supplied XML, " +
			"or move the interface to a non-XML format.",
		Mitigation: "Configure every parser that handles caller-influenced XML to reject DOCTYPE declarations entirely: in Java, " +
			"set the disallow-doctype-decl feature on DocumentBuilderFactory and SAXParserFactory and disable DTD support " +
			"on XMLInputFactory; in .NET, use DtdProcessing.Prohibit with a null XmlResolver; in Python, use defusedxml; " +
			"with libxml2, never enable XML_PARSE_NOENT or XML_PARSE_DTDLOAD. Where DTDs are genuinely required, disable " +
			"external general and parameter entities and external DTD loading, and cap entity expansion to stop " +
			"billion-laughs denial of service. Cover every XML entry point, including SOAP endpoints, SAML assertions, SVG " +
			"uploads, Office documents (DOCX and XLSX are ZIP-wrapped XML), RSS feeds, and XSLT processing. Prefer JSON " +
			"for new interfaces. Restrict filesystem permissions and outbound egress so a missed parser cannot read key " +
			"files or reach internal services. Keep XML libraries and SOAP and SAML frameworks patched. References: " +
			"CWE-611, CWE-776; CAPEC-221 (Data Serialization External Entities Blowup); MITRE ATT&CK T1190; OWASP Top " +
			"10:2025 A02 (Security Misconfiguration).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.InformationDisclosure,
		DetectionLogic: "In-scope technical assets accepting XML data formats.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed. " +
			"Also for cloud-based environments the exploitation impact is at least medium, as cloud backend services can be attacked via SSRF (and XXE vulnerabilities are often also SSRF vulnerabilities).",
		FalsePositives: "Fully trusted (i.e. cryptographically signed or similar) XML data can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        611,
	}
}

func (*XmlExternalEntityRule) SupportedTags() []string {
	return []string{}
}

func (r *XmlExternalEntityRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope {
			continue
		}
		for _, format := range technicalAsset.DataFormatsAccepted {
			if format == types.XML {
				risks = append(risks, r.createRisk(input, technicalAsset))
			}
		}
	}
	return risks, nil
}

func (r *XmlExternalEntityRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>XML External Entity (XXE)</b> risk at <b>" + technicalAsset.Title + "</b>"
	// Narrowed to Confidentiality alone, matching this category's STRIDE value
	// (InformationDisclosure): this category's own Impact text is purely about reading files or
	// accessing services of other components, not modifying them -- the Integrity/Availability
	// checks an earlier version of this rule also had no longer apply, the same reasoning as
	// path_traversal_rule.go's createRisk().
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential {
		impact = types.HighImpact
	}
	likelihood := computeLikelihood(types.VeryLikely, technicalAsset)
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id}, // TODO: use the same logic here as for SSRF rule, as XXE is also SSRF ;)
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
