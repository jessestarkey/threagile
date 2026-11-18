package scripts

// Per-rule tests for the input/output AI rules of the rework plan (#3, #4, #5). Helpers come
// from the other per-rule test files.

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func withAttributes(asset *types.TechnicalAsset, attributes ...string) *types.TechnicalAsset {
	for _, attribute := range attributes {
		asset.Technologies[0].Attributes[attribute] = true
	}
	return asset
}

// --- #3 Hidden Context Exposure ---

//go:embed ai-hidden-context-exposure.yaml
var aiHiddenContextExposure string

func TestHiddenContextExposureFiresOnlyWhenRequestsComeFromOutside(t *testing.T) {
	for _, technology := range []string{"ai-llm-endpoint", "ai-rag-pipeline", "ai-agent-orchestrator"} {
		t.Run(technology, func(t *testing.T) {
			exposed := exposureModel(technology, "dmz", "core")
			exposed.TechnicalAssets["llm"].Confidentiality = types.Confidential
			risks := generateScriptRisks(t, aiHiddenContextExposure, exposed)
			require.Len(t, risks, 1)
			assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
			assert.Equal(t, types.MediumImpact, risks[0].ExploitationImpact)

			assert.Empty(t, generateScriptRisks(t, aiHiddenContextExposure, exposureModel(technology, "core", "core")))
		})
	}
	assert.Empty(t, generateScriptRisks(t, aiHiddenContextExposure, exposureModel("ai-model-serving", "dmz", "core")))
}

// --- #4 Improper Output Handling ---

//go:embed ai-improper-output-handling.yaml
var aiImproperOutputHandling string

func TestImproperOutputHandlingFiresWhenOutputIsConsumed(t *testing.T) {
	monitoringStack := withAttributes(agencyAsset("metrics", "monitoring"), "monitoring")
	db := agencyAsset("db", "database")
	db.Integrity = types.Critical
	backend := agencyAsset("backend", "web-service-rest", agencyLink("backend>called", "called", false))
	backend.Integrity = types.Critical
	model := boundaryModel(map[string]string{},
		backend,
		agencyAsset("called", "ai-llm-endpoint"),
		agencyAsset("telemetry-only", "ai-llm-endpoint", agencyLink("telemetry-only>metrics", "metrics", false)),
		monitoringStack,
		agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>model", "model", false)),
		agencyAsset("model", "ai-llm-endpoint"),
		agencyAsset("writer", "ai-agent-orchestrator", agencyLink("writer>db", "db", false)),
		db,
	)

	fired := firedOn(generateScriptRisks(t, aiImproperOutputHandling, model))

	assert.ElementsMatch(t, []string{"called", "writer"}, keys(fired),
		"called has a caller that consumes its output; writer writes to a datastore; telemetry-only "+
			"only sends metrics; agent only calls its own model; model's only caller is an agent, which "+
			"passes the output on and carries the finding itself where it lands")
	assert.Equal(t, types.HighImpact, fired["called"].ExploitationImpact, "consumed by a critical-integrity backend")
	assert.Equal(t, types.HighImpact, fired["writer"].ExploitationImpact, "output reaches a critical-integrity datastore")
	assert.Equal(t, types.Likely, fired["writer"].ExploitationLikelihood)
}

// --- #5 Unsafe Natural-Language Data Gateway ---

//go:embed ai-unsafe-nl-data-gateway.yaml
var aiUnsafeNLDataGateway string

func TestUnsafeNLDataGatewayFiresOnAIAssetsLinkingToDatastores(t *testing.T) {
	datastore := func(id string, confidentiality types.Confidentiality) *types.TechnicalAsset {
		asset := agencyAsset(id, "database")
		asset.Type = types.Datastore
		asset.Confidentiality = confidentiality
		return asset
	}
	model := secretsSprawlModel(
		withAttributes(agencyAsset("sql-agent", "ai-agent-orchestrator", agencyLink("sql-agent>crm", "crm", true)), "ai"),
		withAttributes(agencyAsset("rag", "ai-rag-pipeline", agencyLink("rag>api", "api", false)), "ai"),
		agencyAsset("app", "web-application", agencyLink("app>crm", "crm", false)),
		datastore("crm", types.StrictlyConfidential),
		agencyAsset("api", "web-service-rest"),
	)

	fired := firedOn(generateScriptRisks(t, aiUnsafeNLDataGateway, model))

	assert.ElementsMatch(t, []string{"sql-agent"}, keys(fired),
		"read-only links count; rag's target is not a datastore; app is not AI")
	assert.Equal(t, types.HighImpact, fired["sql-agent"].ExploitationImpact)
	assert.Equal(t, types.PossibleLikelihood, fired["sql-agent"].ExploitationLikelihood)
}

// Review finding 6: only query-composing AI assets fire, and vector stores are left to #20.
func TestUnsafeNLDataGatewayIgnoresPipelinesAndVectorStores(t *testing.T) {
	datastore := func(id, technology string) *types.TechnicalAsset {
		asset := agencyAsset(id, technology)
		asset.Type = types.Datastore
		return asset
	}
	model := secretsSprawlModel(
		agencyAsset("train", "ai-training-pipeline", agencyLink("train>data", "data", true)),
		agencyAsset("ingest", "ai-rag-ingest-pipeline", agencyLink("ingest>vectors", "vectors", false)),
		agencyAsset("rag", "ai-rag-pipeline", agencyLink("rag>vectors", "vectors", true)),
		agencyAsset("tools", "ai-tool-server", agencyLink("tools>crm", "crm", false)),
		datastore("data", "ai-dataset-store"),
		datastore("vectors", "ai-vector-store"),
		datastore("crm", "database"),
	)

	assert.ElementsMatch(t, []string{"tools"}, keys(firedOn(generateScriptRisks(t, aiUnsafeNLDataGateway, model))),
		"training and ingest pipelines do not compose queries; the RAG pipeline only reaches a vector store")
}
