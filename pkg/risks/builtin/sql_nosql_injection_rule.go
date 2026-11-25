package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type SqlNoSqlInjectionRule struct{}

func NewSqlNoSqlInjectionRule() *SqlNoSqlInjectionRule {
	return &SqlNoSqlInjectionRule{}
}

func (*SqlNoSqlInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "sql-nosql-injection",
		Title: "SQL/NoSQL-Injection",
		Description: "When a database is accessed via database access protocols SQL/NoSQL-Injection risks might arise. " +
			"The risk rating depends on the sensitivity technical asset itself and of the data assets processed.",
		Impact:     "If this risk is unmitigated, attackers might be able to modify SQL/NoSQL queries to steal and modify data and eventually further escalate towards a deeper system penetration via code executions.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		Action: "Use parameterized queries or prepared statements for every database call, prohibit string-built query text, " +
			"and connect with a least-privilege database account.",
		Mitigation: "Execute all SQL with bound parameters (prepared statements, driver placeholders, or ORM query builders), and never concatenate caller input into query text.\n" +
			"Validate identifiers that cannot be parameterized (ORDER BY columns, table names, and sort direction) against a fixed allowlist.\n" +
			"Audit ORM raw-query escapes (such as FromSqlRaw or createNativeQuery) and stored procedures that build dynamic SQL.\n" +
			"For NoSQL stores, reject operator keys such as $where and $ne in caller-supplied JSON, disable server-side JavaScript, and bind input to typed query objects.\n" +
			"Connect with an account limited to the required tables and DML operations, with no DDL, file, OS, or administrative rights, so a successful injection cannot escalate to code execution.\n" +
			"Add SAST rules for injection sinks in CI, and run DAST (sqlmap or ZAP) against staging.\n" +
			"For third-party products, confirm the vendor's query handling, and keep the product patched.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		FindingClass:   types.FindingClassControlNotEvidenced,
		DetectionLogic: "Database accessed via typical database access protocols by in-scope clients.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the database.",
		FalsePositives: "Database accesses by queries not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        89,
	}
}

func (*SqlNoSqlInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *SqlNoSqlInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Type != types.Datastore {
			continue
		}

		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			potentialDatabaseAccessProtocol := incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol()
			isVulnerableToQueryInjection := technicalAsset.Technologies.GetAttribute(types.IsVulnerableToQueryInjection)
			potentialLaxDatabaseAccessProtocol := incomingFlow.Protocol.IsPotentialLaxDatabaseAccessProtocol()
			if potentialDatabaseAccessProtocol && isVulnerableToQueryInjection ||
				potentialLaxDatabaseAccessProtocol {
				risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow))
			}
		}
	}
	return risks, nil
}

func (r *SqlNoSqlInjectionRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>SQL/NoSQL-Injection</b> risk at <b>" + caller.Title + "</b> against database <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	// Impact: baseline plus the CIA step on the higher of the processed confidentiality and integrity
	// (readAndAlterImpact): injection both reads and alters data.
	impact := readAndAlterImpact(input, types.HighImpact, technicalAsset)
	likelihood := types.PossibleLikelihood // DevOps: one level below the baseline, with no RAA/internet step
	if incomingFlow.Usage == types.DevOps {
		// As in the SSRF rule, a DevOps write is not built from caller input, so the RAA and
		// internet steps are skipped.
	} else {
		likelihood = computeLikelihood(types.Likely, technicalAsset)
	}
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
