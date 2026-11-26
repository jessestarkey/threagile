package scripts

// Findings that would restate one already raised elsewhere in the same chain (the 2026-11-18 noise
// review): telemetry only on prompt-handling assets, excessive agency on the agent rather than the
// tool server it steers, and improper output handling where the output lands rather than on the
// model whose output an agent passes on.

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

//go:embed ai-telemetry-prompt-log-leakage.yaml
var aiTelemetryForNoise string

func TestTelemetryLeakageFiresOnlyOnPromptHandlingAssets(t *testing.T) {
	model := withData(secretsSprawlModel(
		processing(agencyAsset("llm", "ai-llm-endpoint"), "secret"),
		processing(agencyAsset("agent", "ai-agent-orchestrator"), "secret"),
		processing(agencyAsset("tools", "ai-tool-server"), "secret"),
		processing(agencyAsset("vectors", "ai-vector-store"), "secret"),
		processing(agencyAsset("ingest", "ai-rag-ingest-pipeline"), "secret"),
	), map[string]types.Confidentiality{"secret": types.Confidential})

	fired := firedOn(generateScriptRisks(t, aiTelemetryForNoise, model))

	assert.ElementsMatch(t, []string{"llm", "agent"}, keys(fired),
		"tool servers, vector stores and ingest pipelines handle data but not prompts")
}

func TestExcessiveAgencyOnToolServerOnlyWhenNoInScopeAgentSteersIt(t *testing.T) {
	steered := boundaryModel(map[string]string{},
		agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>tools", "tools", false)),
		agencyAsset("tools", "ai-tool-server", agencyLink("tools>db", "db", false)),
		agencyAsset("db", "database"),
	)
	assert.ElementsMatch(t, []string{"agent"}, keys(firedOn(generateExcessiveAgencyRisks(t, steered))),
		"the agent decides what the tools do and carries the finding")

	outsideAgent := agencyAsset("partner", "ai-agent-orchestrator", agencyLink("partner>tools", "tools", false))
	outsideAgent.OutOfScope = true
	unsteered := boundaryModel(map[string]string{},
		outsideAgent,
		agencyAsset("tools", "ai-tool-server", agencyLink("tools>db", "db", false)),
		agencyAsset("db", "database"),
	)
	assert.ElementsMatch(t, []string{"tools"}, keys(firedOn(generateExcessiveAgencyRisks(t, unsteered))),
		"with the steering agent out of scope, the tool server carries the finding")
}

func TestImproperOutputHandlingSkipsModelsWhoseOnlyCallerIsAnAgent(t *testing.T) {
	model := boundaryModel(map[string]string{},
		agencyAsset("ui", "web-application", agencyLink("ui>agent", "agent", false)),
		agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>llm", "llm", false)),
		agencyAsset("llm", "ai-llm-endpoint"),
		agencyAsset("app", "web-application", agencyLink("app>direct", "direct", false)),
		agencyAsset("direct", "ai-llm-endpoint"),
	)

	fired := firedOn(generateScriptRisks(t, aiImproperOutputHandling, model))

	assert.ElementsMatch(t, []string{"agent", "direct"}, keys(fired),
		"the agent's output lands in the UI; direct's output lands in an app; llm's only caller is the agent")
}

func TestExcessiveAgencyAgentImpactReachesThroughItsToolServer(t *testing.T) {
	db := agencyAsset("db", "database")
	db.Confidentiality, db.Integrity = types.StrictlyConfidential, types.MissionCritical

	writable := boundaryModel(map[string]string{},
		agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>tools", "tools", false)),
		agencyAsset("tools", "ai-tool-server", agencyLink("tools>db", "db", false)),
		db,
	)
	fired := firedOn(generateExcessiveAgencyRisks(t, writable))
	assert.ElementsMatch(t, []string{"agent"}, keys(fired))
	assert.Equal(t, types.HighImpact, fired["agent"].ExploitationImpact,
		"the agent reaches the strictly-confidential database through its tool server")

	readonly := boundaryModel(map[string]string{},
		agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>tools", "tools", true)),
		agencyAsset("tools", "ai-tool-server", agencyLink("tools>db", "db", false)),
		db,
	)
	fired = firedOn(generateExcessiveAgencyRisks(t, readonly))
	assert.ElementsMatch(t, []string{"tools"}, keys(fired),
		"a read-only agent link does not hand the tools over, so the tool server keeps the finding")
	assert.Equal(t, types.HighImpact, fired["tools"].ExploitationImpact)
}
