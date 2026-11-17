package scripts

// Per-rule tests for the data-group AI rules of the rework plan (#14-#17, #20-#22). Helpers
// come from the other per-rule test files (agencyAsset, agencyLink, secretsSprawlModel,
// generateScriptRisks).

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/types"
)

func withData(model *types.Model, levels map[string]types.Confidentiality) *types.Model {
	model.DataAssets = map[string]*types.DataAsset{}
	for id, level := range levels {
		model.DataAssets[id] = &types.DataAsset{Id: id, Title: id, Confidentiality: level}
	}
	return model
}

func processing(asset *types.TechnicalAsset, dataIds ...string) *types.TechnicalAsset {
	asset.DataAssetsProcessed = dataIds
	return asset
}

func firedOn(risks []*types.Risk) map[string]*types.Risk {
	result := map[string]*types.Risk{}
	for _, risk := range risks {
		result[risk.MostRelevantTechnicalAssetId] = risk
	}
	return result
}

// --- #14 Cross-Context Bleed and Over-Broad Context ---

//go:embed ai-cross-context-bleed.yaml
var aiCrossContextBleed string

func TestCrossContextBleedNeedsARealSensitivityMixInTheContext(t *testing.T) {
	sending := func(id, target string, data ...string) *types.CommunicationLink {
		return &types.CommunicationLink{Id: id, TargetId: target, DataAssetsSent: data}
	}
	retrieving := func(id, target string, data ...string) *types.CommunicationLink {
		return &types.CommunicationLink{Id: id, TargetId: target, DataAssetsReceived: data, Readonly: true}
	}
	stores := func(asset *types.TechnicalAsset, data ...string) *types.TechnicalAsset {
		asset.DataAssetsStored = data
		return asset
	}
	multiTenant := agencyAsset("tenants", "ai-llm-endpoint")
	multiTenant.MultiTenant = true
	model := withData(boundaryModel(map[string]string{},
		multiTenant,
		stores(agencyAsset("stored-mix", "ai-rag-pipeline"), "public", "secret"),
		stores(agencyAsset("harmless-mix", "ai-rag-pipeline"), "public", "internal"),
		// Processes confidential prompts but only *sends* public metrics out: no mix in its context.
		processing(agencyAsset("telemetry", "ai-llm-endpoint", sending("telemetry>metrics", "metrics", "public")), "secret"),
		agencyAsset("metrics", "monitoring"),
		// Callers send confidential data in; it retrieves internal data through a tool.
		agencyAsset("flow-mix", "ai-agent-orchestrator", retrieving("flow-mix>kb", "kb", "internal")),
		agencyAsset("ui", "web-application", sending("ui>flow-mix", "flow-mix", "secret")),
		agencyAsset("kb", "database"),
		processing(agencyAsset("app", "web-application"), "public", "secret"),
	), map[string]types.Confidentiality{"public": types.Public, "internal": types.Internal, "secret": types.Confidential})

	fired := firedOn(generateScriptRisks(t, aiCrossContextBleed, model))

	assert.ElementsMatch(t, []string{"tenants", "stored-mix", "flow-mix"}, keys(fired),
		"harmless-mix is public plus internal; telemetry only sends data out; app is not AI")
	assert.Equal(t, types.PossibleLikelihood, fired["stored-mix"].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, fired["stored-mix"].ExploitationImpact, "confidential data in the context")
	assert.Equal(t, types.HighImpact, fired["flow-mix"].ExploitationImpact)
	assert.Equal(t, types.LowImpact, fired["tenants"].ExploitationImpact, "internal asset, no data")
}

// exposureModel places "client" and "llm" (with the given technology, processing the given data)
// in the named trust boundaries ("" = none) and links client -> llm.
func exposureModel(technology string, clientBoundary, llmBoundary string, data ...string) *types.Model {
	llm := processing(agencyAsset("llm", technology), data...)
	client := agencyAsset("client", "web-application", agencyLink("client>llm", "llm", false))
	client.Technologies[0].Attributes["frontend_related"] = true
	model := withData(secretsSprawlModel(client, llm), map[string]types.Confidentiality{
		"internal": types.Internal, "secret": types.Confidential, "topsecret": types.StrictlyConfidential,
	})
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{}
	for id, boundary := range map[string]string{"client": clientBoundary, "llm": llmBoundary} {
		if boundary != "" {
			model.DirectContainingTrustBoundaryMappedByTechnicalAssetId[id] = &types.TrustBoundary{Id: boundary, Title: boundary}
		}
	}
	model.IncomingTechnicalCommunicationLinksMappedByTargetId = map[string][]*types.CommunicationLink{
		"llm": client.CommunicationLinks,
	}
	return model
}

// --- #15 Sensitive Information Disclosure via Model Output ---

//go:embed ai-sensitive-information-disclosure.yaml
var aiSensitiveInformationDisclosure string

func TestSensitiveDisclosureNeedsConfidentialDataAndOutsideRequests(t *testing.T) {
	tests := []struct {
		name                        string
		clientBoundary, llmBoundary string
		data                        []string
		internet                    bool
		fires                       bool
		impact                      types.RiskExploitationImpact
	}{
		{"confidential, request from another boundary", "dmz", "core", []string{"secret"}, false, true, types.HighImpact},
		{"strictly confidential raises impact", "dmz", "core", []string{"internal", "topsecret"}, false, true, types.VeryHighImpact},
		{"confidential, internet-facing", "core", "core", []string{"secret"}, true, true, types.HighImpact},
		{"confidential, caller outside any boundary", "", "core", []string{"secret"}, false, true, types.HighImpact},
		{"confidential, same boundary only", "core", "core", []string{"secret"}, false, false, 0},
		{"confidential, neither in a boundary", "", "", []string{"secret"}, false, false, 0},
		{"internal data only, outside requests", "dmz", "core", []string{"internal"}, false, false, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := exposureModel("ai-rag-pipeline", test.clientBoundary, test.llmBoundary, test.data...)
			model.TechnicalAssets["llm"].Internet = test.internet

			risks := generateScriptRisks(t, aiSensitiveInformationDisclosure, model)

			if !test.fires {
				assert.Empty(t, risks)
				return
			}
			require.Len(t, risks, 1)
			assert.Equal(t, "llm", risks[0].MostRelevantTechnicalAssetId)
			assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
			assert.Equal(t, test.impact, risks[0].ExploitationImpact)
		})
	}
}

// --- #16 Inference and Training-Data Reconstruction ---

//go:embed ai-inference-data-reconstruction.yaml
var aiInferenceDataReconstruction string

func TestInferenceReconstructionFiresOnExposedInferenceAPIs(t *testing.T) {
	for _, technology := range []string{"ai-llm-endpoint", "ai-model-serving"} {
		t.Run(technology, func(t *testing.T) {
			exposed := exposureModel(technology, "dmz", "core")
			exposed.TechnicalAssets["llm"].Confidentiality = types.Confidential
			risks := generateScriptRisks(t, aiInferenceDataReconstruction, exposed)
			require.Len(t, risks, 1)
			assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)

			assert.Empty(t, generateScriptRisks(t, aiInferenceDataReconstruction, exposureModel(technology, "core", "core")))
		})
	}
	assert.Empty(t, generateScriptRisks(t, aiInferenceDataReconstruction, exposureModel("ai-rag-pipeline", "dmz", "core")),
		"RAG pipelines are covered by sensitive-information-disclosure, not this rule")
}

// --- #17 Model Exfiltration and IP Replication ---

//go:embed ai-model-exfiltration.yaml
var aiModelExfiltration string

func TestModelExfiltrationFiresOnStoresAlwaysAndServingOnlyWhenPhysical(t *testing.T) {
	machine := func(asset *types.TechnicalAsset, m types.TechnicalAssetMachine) *types.TechnicalAsset {
		asset.Machine = m
		return asset
	}
	secretRegistry := agencyAsset("registry", "ai-model-registry")
	secretRegistry.Confidentiality = types.StrictlyConfidential
	model := secretsSprawlModel(
		secretRegistry,
		machine(agencyAsset("training", "ai-training-pipeline"), types.Container),
		machine(agencyAsset("edge", "ai-model-serving"), types.Physical),
		machine(agencyAsset("cloud", "ai-llm-endpoint"), types.Virtual),
		machine(agencyAsset("pod", "ai-model-serving"), types.Container),
		machine(agencyAsset("fn", "ai-llm-endpoint"), types.Serverless),
		machine(agencyAsset("box", "ai-llm-endpoint"), types.Physical),
	)

	fired := firedOn(generateScriptRisks(t, aiModelExfiltration, model))

	assert.ElementsMatch(t, []string{"registry", "training", "edge", "box"}, keys(fired))
	assert.Equal(t, types.VeryHighImpact, fired["registry"].ExploitationImpact)
	assert.Equal(t, types.MediumImpact, fired["edge"].ExploitationImpact, "internal-rated asset")
	assert.Equal(t, types.Likely, fired["edge"].ExploitationLikelihood)
}

func keys(m map[string]*types.Risk) []string {
	result := make([]string, 0, len(m))
	for key := range m {
		result = append(result, key)
	}
	return result
}

// --- #20 Vector Store Exposure and Embedding Inversion ---

//go:embed ai-vector-store-exposure.yaml
var aiVectorStoreExposure string

func TestVectorStoreExposureFiringConditions(t *testing.T) {
	store := func(id string, encryption types.EncryptionStyle, multiTenant bool, stored ...string) *types.TechnicalAsset {
		asset := agencyAsset(id, "ai-vector-store")
		asset.Encryption = encryption
		asset.MultiTenant = multiTenant
		asset.DataAssetsStored = stored
		return asset
	}
	model := withData(secretsSprawlModel(
		store("plain", types.NoneEncryption, false),
		store("shared", types.Transparent, true),
		store("secret", types.Transparent, false, "secret"),
		store("safe", types.Transparent, false, "internal"),
	), map[string]types.Confidentiality{"internal": types.Internal, "secret": types.Confidential})

	fired := firedOn(generateScriptRisks(t, aiVectorStoreExposure, model))

	assert.ElementsMatch(t, []string{"plain", "shared", "secret"}, keys(fired))
	assert.Equal(t, types.HighImpact, fired["secret"].ExploitationImpact)
	assert.Equal(t, types.LowImpact, fired["plain"].ExploitationImpact)
}

// --- #21 Synthetic Data and Anonymization Pitfalls ---

//go:embed ai-synthetic-data-leakage.yaml
var aiSyntheticDataLeakage string

func TestSyntheticDataLeakageNeedsConfidentialSource(t *testing.T) {
	model := withData(secretsSprawlModel(
		processing(agencyAsset("from-secret", "ai-synthetic-data-pipeline"), "internal", "secret"),
		processing(agencyAsset("from-internal", "ai-synthetic-data-pipeline"), "internal"),
		processing(agencyAsset("trainer", "ai-training-pipeline"), "secret"),
	), map[string]types.Confidentiality{"internal": types.Internal, "secret": types.Confidential})

	fired := firedOn(generateScriptRisks(t, aiSyntheticDataLeakage, model))

	assert.ElementsMatch(t, []string{"from-secret"}, keys(fired))
	assert.Equal(t, types.HighImpact, fired["from-secret"].ExploitationImpact)
}

// --- #22 AI Telemetry and Prompt-Log Leakage ---

//go:embed ai-telemetry-prompt-log-leakage.yaml
var aiTelemetryPromptLogLeakage string

func TestTelemetryLeakageFiresOnSensitiveTelemetryLinksAndStores(t *testing.T) {
	telemetry := func(id, target string, data ...string) *types.CommunicationLink {
		return &types.CommunicationLink{Id: id, TargetId: target, DataAssetsSent: data}
	}
	observability := agencyAsset("obs", "ai-observability-stack")
	observability.Technologies[0].Attributes["monitoring"] = true
	observability.DataAssetsStored = []string{"topsecret"}
	model := withData(secretsSprawlModel(
		agencyAsset("llm", "ai-llm-endpoint", telemetry("llm>obs", "obs", "internal", "secret")),
		agencyAsset("agent", "ai-agent-orchestrator", telemetry("agent>siem", "siem", "internal")),
		agencyAsset("rag", "ai-rag-pipeline", telemetry("rag>db", "db", "topsecret")),
		agencyAsset("app", "web-application", telemetry("app>obs", "obs", "topsecret")),
		observability,
		agencyAsset("siem", "siem"),
		agencyAsset("db", "database"),
	), map[string]types.Confidentiality{
		"internal": types.Internal, "secret": types.Confidential, "topsecret": types.StrictlyConfidential,
	})
	model.TechnicalAssets["siem"].Technologies[0].Attributes["monitoring"] = true
	// The real catalogue gives every AI technology the ai attribute; agencyAsset doesn't.
	for _, id := range []string{"llm", "agent", "rag", "obs"} {
		model.TechnicalAssets[id].Technologies[0].Attributes["ai"] = true
	}

	fired := firedOn(generateScriptRisks(t, aiTelemetryPromptLogLeakage, model))
	require.Contains(t, fired, "llm")
	require.Contains(t, fired, "obs")

	assert.ElementsMatch(t, []string{"llm", "obs"}, keys(fired),
		"llm sends confidential telemetry; obs holds strictly confidential data; agent sends only internal; rag's link is not telemetry; app is not AI")
	assert.Equal(t, types.HighImpact, fired["llm"].ExploitationImpact)
	assert.Equal(t, types.VeryHighImpact, fired["obs"].ExploitationImpact)
}

//go:embed cui-telemetry-spillage.yaml
var cuiTelemetrySpillage string

func TestCuiTelemetrySpillageSkipsAIAssets(t *testing.T) {
	llm := agencyAsset("llm", "ai-llm-endpoint")
	llm.Technologies[0].Attributes["ai"] = true
	llm.Technologies[0].Attributes["application_logic"] = true
	app := agencyAsset("app", "web-application")
	app.Technologies[0].Attributes["application_logic"] = true

	fired := firedOn(generateScriptRisks(t, cuiTelemetrySpillage, secretsSprawlModel(llm, app)))

	assert.ElementsMatch(t, []string{"app"}, keys(fired))
}

// Limits round: an AI asset handling confidential data is in scope without a drawn telemetry
// link (tracing captures prompts by default); a drawn link carrying the data raises likelihood.
func TestTelemetryLeakageFiresWithoutADrawnLinkAndRisesWithOne(t *testing.T) {
	ai := func(asset *types.TechnicalAsset) *types.TechnicalAsset {
		asset.Technologies[0].Attributes["ai"] = true
		return asset
	}
	undrawn := processing(ai(agencyAsset("undrawn", "ai-llm-endpoint")), "secret")
	drawn := processing(ai(agencyAsset("drawn", "ai-llm-endpoint",
		&types.CommunicationLink{Id: "drawn>obs", TargetId: "obs", DataAssetsSent: []string{"secret"}})), "secret")
	internalOnly := processing(ai(agencyAsset("internal-only", "ai-llm-endpoint")), "internal")
	observability := ai(agencyAsset("obs", "ai-observability-stack"))
	model := withData(secretsSprawlModel(undrawn, drawn, internalOnly, observability),
		map[string]types.Confidentiality{"internal": types.Internal, "secret": types.Confidential})

	fired := firedOn(generateScriptRisks(t, aiTelemetryPromptLogLeakage, model))

	assert.ElementsMatch(t, []string{"undrawn", "drawn"}, keys(fired), "internal-only has nothing confidential")
	assert.Equal(t, types.Likely, fired["undrawn"].ExploitationLikelihood)
	assert.Equal(t, types.VeryLikely, fired["drawn"].ExploitationLikelihood)
}

// --- DSGAI17 AI Retrieval and Index Resilience Gap ---

//go:embed ai-retrieval-resilience-gap.yaml
var aiRetrievalResilienceGap string

func TestRetrievalResilienceFiresOnCriticalRetrievalCapabilitiesOnly(t *testing.T) {
	rated := func(id, technology string, availability types.Criticality) *types.TechnicalAsset {
		asset := agencyAsset(id, technology)
		asset.Availability = availability
		return asset
	}
	model := secretsSprawlModel(
		rated("vectors", "ai-vector-store", types.MissionCritical),
		rated("features", "ai-feature-store", types.Critical),
		rated("rag", "ai-rag-pipeline", types.Critical),
		rated("minor-rag", "ai-rag-pipeline", types.Important),
		rated("db", "database", types.MissionCritical),
	)

	fired := firedOn(generateScriptRisks(t, aiRetrievalResilienceGap, model))

	assert.ElementsMatch(t, []string{"vectors", "features", "rag"}, keys(fired))
	assert.Equal(t, types.PossibleLikelihood, fired["rag"].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, fired["vectors"].ExploitationImpact)
}
