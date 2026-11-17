package scripts

// Per-rule tests for the integrity-group AI rules of the rework plan (#18, #19, #23, #25) and
// the narrowed adversarial-evasion rule (#34). Helpers come from the other per-rule test files.

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

// boundaryModel builds a model from the assets, puts each listed asset into the named trust
// boundary, and indexes incoming links the same way the Threagile parser does.
func boundaryModel(boundaries map[string]string, assets ...*types.TechnicalAsset) *types.Model {
	model := secretsSprawlModel(assets...)
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{}
	for id, boundary := range boundaries {
		model.DirectContainingTrustBoundaryMappedByTechnicalAssetId[id] = &types.TrustBoundary{Id: boundary, Title: boundary}
	}
	model.IncomingTechnicalCommunicationLinksMappedByTargetId = map[string][]*types.CommunicationLink{}
	for _, asset := range assets {
		for _, link := range asset.CommunicationLinks {
			model.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId] = append(
				model.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId], link)
		}
	}
	return model
}

// --- #18 Training and Fine-Tuning Data and Model Poisoning ---

//go:embed ai-training-data-model-poisoning.yaml
var aiTrainingDataModelPoisoning string

func TestTrainingPoisoningFiresOnTrainingAssetsWithOutsideWritesRaisingLikelihood(t *testing.T) {
	model := boundaryModel(
		map[string]string{"feed": "partner", "reader": "partner", "train": "ml", "data": "ml", "features": "ml", "eval": "ml"},
		agencyAsset("feed", "web-service-rest", agencyLink("feed>data", "data", false)),
		agencyAsset("reader", "web-service-rest", agencyLink("reader>features", "features", true)),
		agencyAsset("train", "ai-training-pipeline"),
		agencyAsset("data", "ai-dataset-store"),
		agencyAsset("features", "ai-feature-store"),
		agencyAsset("eval", "ai-eval-pipeline"),
		agencyAsset("llm", "ai-llm-endpoint"),
	)
	model.TechnicalAssets["train"].Integrity = types.Critical

	fired := firedOn(generateScriptRisks(t, aiTrainingDataModelPoisoning, model))

	assert.ElementsMatch(t, []string{"train", "data", "features", "eval"}, keys(fired))
	assert.Equal(t, types.PossibleLikelihood, fired["data"].ExploitationLikelihood, "written from another boundary")
	assert.Equal(t, types.Unlikely, fired["features"].ExploitationLikelihood, "outside link is read-only")
	assert.Equal(t, types.Unlikely, fired["eval"].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, fired["train"].ExploitationImpact)
	assert.Equal(t, types.LowImpact, fired["eval"].ExploitationImpact)
}

// --- #19 RAG Corpus Poisoning ---

//go:embed ai-rag-corpus-poisoning.yaml
var aiRagCorpusPoisoning string

func TestRagCorpusPoisoningNeedsContentFromOutside(t *testing.T) {
	model := boundaryModel(
		map[string]string{"web": "internet", "pull": "core", "push": "core", "internal": "core", "wiki": "core", "src": "partner"},
		agencyAsset("web", "web-server"),
		agencyAsset("wiki", "web-server"),
		agencyAsset("pull", "ai-rag-ingest-pipeline", agencyLink("pull>web", "web", true)),
		agencyAsset("internal", "ai-rag-ingest-pipeline", agencyLink("internal>wiki", "wiki", true)),
		agencyAsset("push", "ai-rag-pipeline"),
		agencyAsset("src", "web-service-rest", agencyLink("src>push", "push", false)),
	)

	fired := firedOn(generateScriptRisks(t, aiRagCorpusPoisoning, model))

	assert.ElementsMatch(t, []string{"pull", "push"}, keys(fired),
		"pull reads from another boundary; push receives from another boundary; internal only reads inside")
	assert.Equal(t, types.Likely, fired["pull"].ExploitationLikelihood)
}

// --- #23 AI Supply Chain Compromise ---

//go:embed ai-supply-chain-compromise.yaml
var aiSupplyChainCompromise string

func TestSupplyChainFiresOnLoadersAndRisesWhenPullingFromOutside(t *testing.T) {
	model := boundaryModel(
		map[string]string{"hub": "internet", "registry": "core", "serving": "core", "agent": "core", "tools": "core"},
		agencyAsset("hub", "web-server"),
		agencyAsset("registry", "ai-model-registry", agencyLink("registry>hub", "hub", true)),
		agencyAsset("serving", "ai-model-serving", agencyLink("serving>registry", "registry", true)),
		agencyAsset("agent", "ai-agent-orchestrator"),
		agencyAsset("tools", "ai-tool-server"),
		agencyAsset("llm", "ai-llm-endpoint"),
	)
	model.TechnicalAssets["serving"].Integrity = types.Critical

	fired := firedOn(generateScriptRisks(t, aiSupplyChainCompromise, model))

	assert.ElementsMatch(t, []string{"registry", "serving", "agent", "tools"}, keys(fired))
	assert.Equal(t, types.Likely, fired["registry"].ExploitationLikelihood, "pulls from a public hub")
	assert.Equal(t, types.PossibleLikelihood, fired["serving"].ExploitationLikelihood, "pulls from the internal registry")
	assert.Equal(t, types.VeryHighImpact, fired["serving"].ExploitationImpact)
	assert.Equal(t, types.HighImpact, fired["agent"].ExploitationImpact)
}

// --- #25 Unbounded Consumption ---

//go:embed ai-unbounded-consumption.yaml
var aiUnboundedConsumption string

func TestUnboundedConsumptionFiresWhenExposedAndStepsDownBehindGateway(t *testing.T) {
	model := boundaryModel(
		map[string]string{"client": "dmz", "gateway": "core", "direct": "core", "fronted": "core", "inside": "core", "gateway-b": "edge"},
		agencyAsset("client", "web-application",
			agencyLink("client>gateway", "gateway", false), agencyLink("client>direct", "direct", false)),
		agencyAsset("gateway", "ai-gateway", agencyLink("gateway>inside", "inside", false)),
		agencyAsset("gateway-b", "ai-gateway", agencyLink("gateway-b>fronted", "fronted", false)),
		agencyAsset("direct", "ai-llm-endpoint"),
		agencyAsset("fronted", "ai-llm-endpoint"),
		agencyAsset("inside", "ai-llm-endpoint"),
	)

	fired := firedOn(generateScriptRisks(t, aiUnboundedConsumption, model))

	assert.ElementsMatch(t, []string{"gateway", "direct", "fronted"}, keys(fired),
		"inside is reached only from the same boundary; gateway-b receives nothing")
	assert.Equal(t, types.Likely, fired["direct"].ExploitationLikelihood)
	assert.Equal(t, types.PossibleLikelihood, fired["fronted"].ExploitationLikelihood, "only reached through a gateway")
	assert.Equal(t, types.Likely, fired["gateway"].ExploitationLikelihood)
}

// --- #34 Adversarial Evasion (narrowed to model serving) ---

//go:embed ai-adversarial-evasion.yaml
var aiAdversarialEvasion string

func TestAdversarialEvasionFiresOnModelServingOnly(t *testing.T) {
	model := secretsSprawlModel(agencyAsset("classifier", "ai-model-serving"), agencyAsset("llm", "ai-llm-endpoint"))

	assert.ElementsMatch(t, []string{"classifier"}, keys(firedOn(generateScriptRisks(t, aiAdversarialEvasion, model))))
}
