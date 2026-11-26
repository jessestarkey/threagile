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

// external marks an asset as outside the organization: an out-of-scope external entity.
func external(asset *types.TechnicalAsset) *types.TechnicalAsset {
	asset.Type = types.ExternalEntity
	asset.OutOfScope = true
	return asset
}

// frontend marks an asset as frontend-related (web application, reverse proxy, client, ...).
func frontend(asset *types.TechnicalAsset) *types.TechnicalAsset {
	asset.Technologies[0].Attributes["frontend_related"] = true
	return asset
}

func TestTrainingPoisoningFiresOnTrainingAssetsWithOutsideWritesRaisingLikelihood(t *testing.T) {
	model := boundaryModel(
		map[string]string{"backend": "partner", "train": "ml", "data": "ml", "features": "ml", "eval": "ml"},
		external(agencyAsset("feed", "web-service-rest", agencyLink("feed>data", "data", false))),
		external(agencyAsset("reader", "web-service-rest", agencyLink("reader>features", "features", true))),
		agencyAsset("backend", "web-service-rest", agencyLink("backend>eval", "eval", false)),
		agencyAsset("train", "ai-training-pipeline"),
		agencyAsset("data", "ai-dataset-store"),
		agencyAsset("features", "ai-feature-store"),
		agencyAsset("eval", "ai-eval-pipeline"),
		agencyAsset("llm", "ai-llm-endpoint"),
	)
	model.TechnicalAssets["train"].Integrity = types.Critical

	fired := firedOn(generateScriptRisks(t, aiTrainingDataModelPoisoning, model))

	assert.ElementsMatch(t, []string{"train", "data", "features", "eval"}, keys(fired))
	assert.Equal(t, types.PossibleLikelihood, fired["data"].ExploitationLikelihood, "an external feed writes into it")
	assert.Equal(t, types.Unlikely, fired["features"].ExploitationLikelihood, "the external link is read-only")
	assert.Equal(t, types.Unlikely, fired["eval"].ExploitationLikelihood, "an internal backend in another boundary is not outside")
	assert.Equal(t, types.HighImpact, fired["train"].ExploitationImpact)
	assert.Equal(t, types.LowImpact, fired["eval"].ExploitationImpact)
}

func TestTrainingPoisoningTakesOnlyTheInternetStepForItsOwnFlag(t *testing.T) {
	store := agencyAsset("data", "ai-dataset-store")
	store.Internet = true

	fired := firedOn(generateScriptRisks(t, aiTrainingDataModelPoisoning, boundaryModel(map[string]string{}, store)))

	assert.Equal(t, types.PossibleLikelihood, fired["data"].ExploitationLikelihood,
		"the internet step that every rule takes, and no outside-writer step, since nothing writes to it")
}

func TestTrainingPoisoningDropsTheWriterStepOnAnExposedAsset(t *testing.T) {
	store := agencyAsset("data", "ai-dataset-store")
	store.InternetReachable = true
	writer := external(agencyAsset("src", "web-service-rest", agencyLink("src>data", "data", false)))

	fired := firedOn(generateScriptRisks(t, aiTrainingDataModelPoisoning, boundaryModel(map[string]string{}, store, writer)))

	assert.Equal(t, types.PossibleLikelihood, fired["data"].ExploitationLikelihood,
		"one step for the outside reach, the internet step, rather than two")

	unexposed := agencyAsset("data", "ai-dataset-store")
	writer = external(agencyAsset("src", "web-service-rest", agencyLink("src>data", "data", false)))
	fired = firedOn(generateScriptRisks(t, aiTrainingDataModelPoisoning, boundaryModel(map[string]string{}, unexposed, writer)))
	assert.Equal(t, types.PossibleLikelihood, fired["data"].ExploitationLikelihood, "the writer step on an asset that is not exposed")
}

// --- #19 RAG Corpus Poisoning ---

//go:embed ai-rag-corpus-poisoning.yaml
var aiRagCorpusPoisoning string

func TestRagCorpusPoisoningNeedsContentFromOutside(t *testing.T) {
	model := boundaryModel(
		map[string]string{"pull": "core", "push": "core", "queried": "core", "internal": "core", "wiki": "core", "ui": "dmz"},
		external(agencyAsset("web", "web-server")),
		agencyAsset("wiki", "web-server"),
		agencyAsset("pull", "ai-rag-ingest-pipeline", agencyLink("pull>web", "web", true)),
		agencyAsset("internal", "ai-rag-ingest-pipeline", agencyLink("internal>wiki", "wiki", true)),
		agencyAsset("push", "ai-rag-pipeline"),
		agencyAsset("queried", "ai-rag-pipeline"),
		external(agencyAsset("src", "web-service-rest", agencyLink("src>push", "push", false))),
		frontend(agencyAsset("ui", "web-application", agencyLink("ui>queried", "queried", true))),
	)

	fired := firedOn(generateScriptRisks(t, aiRagCorpusPoisoning, model))

	assert.ElementsMatch(t, []string{"pull", "push"}, keys(fired),
		"pull reads from an external source; push is written by an external source; queried only gets read-only user queries; internal only reads inside")
	assert.Equal(t, types.Likely, fired["pull"].ExploitationLikelihood)
}

// --- #23 AI Supply Chain Compromise ---

//go:embed ai-supply-chain-compromise.yaml
var aiSupplyChainCompromise string

func TestSupplyChainFiresOnLoadersAndRisesOnlyWhenPullingFromOutside(t *testing.T) {
	model := boundaryModel(
		map[string]string{"registry": "core", "serving": "core", "agent": "core", "tools": "core", "ui": "dmz"},
		external(agencyAsset("hub", "web-server")),
		agencyAsset("registry", "ai-model-registry", agencyLink("registry>hub", "hub", true)),
		agencyAsset("serving", "ai-model-serving", agencyLink("serving>registry", "registry", true)),
		frontend(agencyAsset("ui", "web-application", agencyLink("ui>serving", "serving", false))),
		agencyAsset("agent", "ai-agent-orchestrator"),
		agencyAsset("tools", "ai-tool-server"),
		agencyAsset("llm", "ai-llm-endpoint"),
	)
	model.TechnicalAssets["serving"].Integrity = types.Critical
	model.TechnicalAssets["agent"].Internet = true

	fired := firedOn(generateScriptRisks(t, aiSupplyChainCompromise, model))

	assert.ElementsMatch(t, []string{"registry", "serving", "agent", "tools"}, keys(fired))
	assert.Equal(t, types.Likely, fired["registry"].ExploitationLikelihood, "pulls from a public hub")
	assert.Equal(t, types.PossibleLikelihood, fired["serving"].ExploitationLikelihood, "pulls from the internal registry; user callers do not count")
	assert.Equal(t, types.Likely, fired["agent"].ExploitationLikelihood,
		"the internet step that every rule takes, while being internet-facing is not a supply-chain pull")
	assert.Equal(t, types.VeryHighImpact, fired["serving"].ExploitationImpact)
	assert.Equal(t, types.MediumImpact, fired["agent"].ExploitationImpact)
}

// --- #25 Unbounded Consumption ---

//go:embed ai-unbounded-consumption.yaml
var aiUnboundedConsumption string

func TestUnboundedConsumptionFiresOnlyWhereOutsideCallersArrive(t *testing.T) {
	model := boundaryModel(
		map[string]string{"ui": "dmz", "gateway": "core", "direct": "core", "behind": "core", "backend": "partner", "internal": "core"},
		frontend(agencyAsset("ui", "web-application",
			agencyLink("ui>gateway", "gateway", false), agencyLink("ui>direct", "direct", false))),
		agencyAsset("gateway", "ai-gateway", agencyLink("gateway>behind", "behind", false)),
		agencyAsset("backend", "web-service-rest", agencyLink("backend>internal", "internal", false)),
		agencyAsset("direct", "ai-llm-endpoint"),
		agencyAsset("behind", "ai-llm-endpoint"),
		agencyAsset("internal", "ai-llm-endpoint"),
	)

	fired := firedOn(generateScriptRisks(t, aiUnboundedConsumption, model))

	assert.ElementsMatch(t, []string{"gateway", "direct"}, keys(fired),
		"behind is reached only through the gateway, which carries the finding; internal is called by a non-frontend backend in another boundary")
	assert.Equal(t, types.Likely, fired["direct"].ExploitationLikelihood)
}

// Execution-environment boundaries are looked through to the enclosing network boundary, matching
// the network-only semantics of the built-in Threagile rules.
func TestOutsideCallerLooksThroughExecutionEnvironmentBoundaries(t *testing.T) {
	ui := frontend(agencyAsset("ui", "web-application", agencyLink("ui>llm", "llm", false)))
	model := boundaryModel(map[string]string{}, ui, agencyAsset("llm", "ai-llm-endpoint"))
	podA := &types.TrustBoundary{Id: "pod-a", Title: "pod-a", Type: types.ExecutionEnvironment}
	podB := &types.TrustBoundary{Id: "pod-b", Title: "pod-b", Type: types.ExecutionEnvironment}
	vpc := &types.TrustBoundary{Id: "vpc", Title: "vpc", Type: types.NetworkCloudProvider, TrustBoundariesNested: []string{"pod-a", "pod-b"}}
	model.TrustBoundaries = map[string]*types.TrustBoundary{"vpc": vpc, "pod-a": podA, "pod-b": podB}
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{"ui": podA, "llm": podB}

	assert.Empty(t, generateScriptRisks(t, aiUnboundedConsumption, model), "both pods sit in the same network boundary")

	vpc.TrustBoundariesNested = []string{"pod-b"}
	model.TrustBoundaries["dmz"] = &types.TrustBoundary{Id: "dmz", Title: "dmz", Type: types.NetworkCloudSecurityGroup, TrustBoundariesNested: []string{"pod-a"}}
	assert.Len(t, generateScriptRisks(t, aiUnboundedConsumption, model), 1, "the pods sit in different network boundaries")
}

// --- #34 Adversarial Evasion (narrowed to model serving) ---

//go:embed ai-adversarial-evasion.yaml
var aiAdversarialEvasion string

func TestAdversarialEvasionFiresOnModelServingOnly(t *testing.T) {
	model := secretsSprawlModel(agencyAsset("classifier", "ai-model-serving"), agencyAsset("llm", "ai-llm-endpoint"))

	assert.ElementsMatch(t, []string{"classifier"}, keys(firedOn(generateScriptRisks(t, aiAdversarialEvasion, model))))
}
