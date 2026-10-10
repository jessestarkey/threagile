package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type SearchQueryInjectionRule struct{}

func NewSearchQueryInjectionRule() *SearchQueryInjectionRule {
	return &SearchQueryInjectionRule{}
}

func (*SearchQueryInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "search-query-injection",
		Title: "Search-Query Injection",
		Description: "When a search engine server is accessed Search-Query Injection risks might arise." +
			"<br><br>See for example <a href=\"https://github.com/veracode-research/solr-injection\">https://github.com/veracode-research/solr-injection</a> and " +
			"<a href=\"https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf\">https://github.com/veracode-research/solr-injection/blob/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf</a> " +
			"for more details (here related to Solr, but in general showcasing the topic of search query injections).",
		Impact: "If this risk remains unmitigated, attackers might be able to read more data from the search index and " +
			"eventually further escalate towards a deeper system penetration via code executions.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
		Action: "Build search queries with the client library's structured query API and escaped user terms, never by " +
			"concatenating caller input into query strings, and never forward caller parameters to the engine unfiltered.",
		Mitigation: "Construct queries with the search client's typed query builders (Elasticsearch or OpenSearch Query DSL " +
			"objects, SolrJ parameter APIs) and pass user input only as term or match values, not as raw query_string or " +
			"Lucene syntax; where users must write query syntax, use simple_query_string with restricted flags. Escape " +
			"Lucene and Solr special characters in user terms. Never pass caller-controlled request parameters through to " +
			"the engine: Solr local parameters, qt, shards, stream.url, and the Velocity response writer, and " +
			"Elasticsearch scripted queries, have each enabled remote code execution or SSRF in real deployments (for " +
			"example CVE-2017-12629, CVE-2019-17558). Enforce document-level security in the query itself or the engine's " +
			"security plugin so a modified query cannot return records outside the caller's authorization. Keep the engine " +
			"off the public network, require authentication on its API, disable dynamic scripting where unused, and keep " +
			"it patched. References: CWE-943, CWE-74; MITRE ATT&CK T1190; OWASP Top 10:2025 A05 (Injection).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope clients accessing search engine servers via typical search access protocols.",
		RiskAssessment: "The risk rating depends on the sensitivity of the search engine server itself and of the data assets processed.",
		FalsePositives: "Server engine queries by search values not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        74,
	}
}

func (*SearchQueryInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *SearchQueryInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if !technicalAsset.Technologies.GetAttribute(types.IsSearchRelated) {
			continue
		}
		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if input.TechnicalAssets[incomingFlow.SourceId].OutOfScope {
				continue
			}
			if incomingFlow.Protocol != types.HTTP && incomingFlow.Protocol != types.HTTPS &&
				incomingFlow.Protocol != types.BINARY && incomingFlow.Protocol != types.BinaryEncrypted {
				continue
			}
			likelihood := types.VeryLikely
			if incomingFlow.Usage == types.DevOps {
				likelihood = types.Likely
			}
			risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow, likelihood))
		}
	}
	return risks, nil
}

func (r *SearchQueryInjectionRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink, likelihood types.RiskExploitationLikelihood) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Search Query Injection</b> risk at <b>" + caller.Title + "</b> against search engine server <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	// Impact intentionally stays keyed off both Confidentiality and Integrity rather than
	// narrowing to just Integrity (this category's own STRIDE value): per this category's own
	// Impact text, search query injection lets an attacker "read more data ... and eventually
	// further escalate towards a deeper system penetration" -- a disclosure consequence first,
	// a tampering one as it escalates.
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	} else if input.HighestProcessedConfidentiality(technicalAsset) <= types.Internal && input.HighestProcessedIntegrity(technicalAsset) == types.Operational {
		impact = types.LowImpact
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
