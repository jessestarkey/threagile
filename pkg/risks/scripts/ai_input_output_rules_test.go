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
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)

			assert.Empty(t, generateScriptRisks(t, aiHiddenContextExposure, exposureModel(technology, "core", "core")))
		})
	}
	assert.Empty(t, generateScriptRisks(t, aiHiddenContextExposure, exposureModel("ai-model-serving", "dmz", "core")))
}

// --- #4 Improper Output Handling ---

//go:embed ai-improper-output-handling.yaml
var aiImproperOutputHandling string

func TestImproperOutputHandlingFiresWhenOutputReachesASink(t *testing.T) {
	browserUI := withAttributes(agencyAsset("ui", "web-application", agencyLink("ui>rendered", "rendered", false)), "frontend_related")
	batch := agencyAsset("batch", "batch-processing", agencyLink("batch>silent", "silent", false))
	model := boundaryModel(map[string]string{},
		browserUI,
		batch,
		agencyAsset("rendered", "ai-llm-endpoint"),
		agencyAsset("silent", "ai-llm-endpoint"),
		agencyAsset("writer", "ai-agent-orchestrator", agencyLink("writer>db", "db", false)),
		agencyAsset("db", "database"),
	)
	model.TechnicalAssets["db"].Integrity = types.Critical

	fired := firedOn(generateScriptRisks(t, aiImproperOutputHandling, model))

	assert.ElementsMatch(t, []string{"rendered", "writer"}, keys(fired),
		"rendered is called by a UI; writer has an outgoing link; silent is only called by a non-rendering batch job")
	assert.Equal(t, types.HighImpact, fired["rendered"].ExploitationImpact)
	assert.Equal(t, types.VeryHighImpact, fired["writer"].ExploitationImpact, "output reaches a critical-integrity datastore")
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
	assert.Equal(t, types.Likely, fired["sql-agent"].ExploitationLikelihood)
}
