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
		Mitigation: "Execute all SQL with bound parameters (JDBC PreparedStatement, ADO.NET SqlParameter, driver placeholders, ORM " +
			"query builders) and never concatenate or format caller input into query text. Identifiers that cannot be " +
			"parameterized (ORDER BY columns, table names, sort direction) must be validated against a fixed allowlist. " +
			"Audit ORM raw-query escapes (raw(), FromSqlRaw, createNativeQuery, text()) and stored procedures that build " +
			"dynamic SQL internally. For NoSQL stores, reject operator keys in caller-supplied JSON (MongoDB $where, $ne, " +
			"$gt, $regex), disable server-side JavaScript execution, and bind input to typed query objects. Connect with " +
			"an account limited to the specific tables and DML operations required, with no DDL, no file or OS access " +
			"(xp_cmdshell, COPY ... PROGRAM, LOAD_FILE, INTO OUTFILE), and no administrative rights, so a successful " +
			"injection cannot escalate to code execution. Add SAST rules for injection sinks in CI and DAST (sqlmap, ZAP) " +
			"against staging. For third-party products, confirm the vendor's query handling and keep the product patched. " +
			"References: CWE-89, CWE-943; CAPEC-66 (SQL Injection), CAPEC-676 (NoSQL Injection); MITRE ATT&CK T1190; OWASP " +
			"Top 10:2025 A05 (Injection).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
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
	// Impact intentionally stays keyed off both Confidentiality and Integrity rather than
	// narrowing to just Integrity (this category's own STRIDE value): per this category's own
	// Impact text, SQL/NoSQL injection lets an attacker "steal and modify data" -- both a
	// confidentiality and an integrity consequence, not just the latter (see
	// docs/risk-methodology.md's discussion of this exact category as a known multi-dimensional
	// case in the custom engine).
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood := types.VeryLikely
	if incomingFlow.Usage == types.DevOps {
		// Same rationale as the SSRF rule's DevOps branch: the asset-level RAA/internet-
		// reachability delta answers "is this component worth attacking in general," not
		// "is this specific query built from caller-controlled input" -- DevOps usage already
		// answers no to the latter, so skip the delta rather than let general attractiveness
		// re-inflate a write that isn't an injection vector regardless of it.
		likelihood = types.Likely
	} else {
		likelihood = computeLikelihood(likelihood, technicalAsset)
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
