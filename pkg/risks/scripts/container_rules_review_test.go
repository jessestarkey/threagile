package scripts

// Container and logging rules after the 2026-11-18 review of the non-AI script rules.

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks/builtin"
	"github.com/threagile/threagile/pkg/types"
)

//go:embed missing-network-micro-segmentation.yaml
var missingNetworkMicroSegmentation string

func container(id string) *types.TechnicalAsset {
	asset := agencyAsset(id, "web-application")
	asset.Machine = types.Container
	return asset
}

func TestMicroSegmentationSkipsContainersInAnIsolatedNamespace(t *testing.T) {
	cluster := &types.TrustBoundary{Id: "cluster", Type: types.NetworkCloudSecurityGroup, TrustBoundariesNested: []string{"ns", "outer-ns"}}
	namespace := &types.TrustBoundary{Id: "ns", Type: types.NetworkPolicyNamespaceIsolation}
	outerNamespace := &types.TrustBoundary{Id: "outer-ns", Type: types.NetworkPolicyNamespaceIsolation, TrustBoundariesNested: []string{"pod-env"}}
	podEnv := &types.TrustBoundary{Id: "pod-env", Type: types.ExecutionEnvironment}

	model := secretsSprawlModel(container("in-ns"), container("nested"), container("in-cluster"), container("loose"))
	model.TrustBoundaries = map[string]*types.TrustBoundary{
		"cluster": cluster, "ns": namespace, "outer-ns": outerNamespace, "pod-env": podEnv,
	}
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{
		"in-ns": namespace, "nested": podEnv, "in-cluster": cluster,
	}

	fired := firedOn(generateScriptRisks(t, missingNetworkMicroSegmentation, model))

	assert.ElementsMatch(t, []string{"in-cluster", "loose"}, keys(fired),
		"in-ns and nested (namespace one level up) show the control; the others don't")
}

func TestClusterAuditGapFiresOncePerClusterAndOnLoneContainers(t *testing.T) {
	a, b, lone, gone := container("a"), container("b"), container("lone"), container("gone")
	a.RAA, b.RAA = 20, 45 // b is the most attractive container on the cluster: likelihood follows it
	b.Integrity = types.MissionCritical
	gone.OutOfScope = true
	model := secretsSprawlModel(a, b, lone, gone, agencyAsset("vm", "web-application"))
	model.SharedRuntimes = map[string]*types.SharedRuntime{
		"cluster": {Id: "cluster", Title: "Cluster", TechnicalAssetsRunning: []string{"a", "b", "vm"}},
	}

	risks, err := builtin.NewClusterControlPlaneAuditGapRule().GenerateRisks(model)
	assert.NoError(t, err)

	subjects := map[string]*types.Risk{}
	for _, risk := range risks {
		subjects[risk.MostRelevantSharedRuntimeId+risk.MostRelevantTechnicalAssetId] = risk
	}
	assert.ElementsMatch(t, []string{"cluster", "lone"}, keysOf(subjects),
		"one finding for the cluster, one for the container on no runtime, none for the out-of-scope one")
	cluster := subjects["cluster"]
	assert.Equal(t, "cluster", cluster.MostRelevantSharedRuntimeId)
	assert.ElementsMatch(t, []string{"a", "b"}, cluster.DataBreachTechnicalAssetIDs, "only the containers on it")
	assert.Equal(t, types.VeryLikely, cluster.ExploitationLikelihood, "Likely plus the RAA step of b (45)")
	assert.Equal(t, types.MediumImpact, cluster.ExploitationImpact, "Low plus the step for b's mission-critical integrity")
}

func keysOf(m map[string]*types.Risk) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestTelemetrySpillageNeedsSensitiveData(t *testing.T) {
	app := func(id string) *types.TechnicalAsset {
		asset := agencyAsset(id, "web-application")
		asset.Technologies[0].Attributes["application_logic"] = true
		return asset
	}
	ownRating := app("own-rating")
	ownRating.Confidentiality = types.Confidential
	model := withData(secretsSprawlModel(
		ownRating,
		processing(app("processes-secret"), "secret"),
		processing(app("internal-only"), "internal"),
	), map[string]types.Confidentiality{"internal": types.Internal, "secret": types.Confidential})

	fired := firedOn(generateScriptRisks(t, cuiTelemetrySpillage, model))

	assert.ElementsMatch(t, []string{"own-rating", "processes-secret"}, keys(fired),
		"logs can only spill data the asset handles")
}

//go:embed vulnerable-outdated-dependency.yaml
var vulnerableOutdatedDependencyForReview string

//go:embed os-command-injection.yaml
var osCommandInjectionForReview string

func TestDependencyAndCommandInjectionRulesSkipExternalEntities(t *testing.T) {
	custom := func(id string, assetType types.TechnicalAssetType) *types.TechnicalAsset {
		asset := agencyAsset(id, "web-application")
		asset.Type = assetType // agencyAsset defaults to process; ExternalEntity is the dropped zero value
		asset.CustomDevelopedParts = true
		asset.Technologies[0].Attributes["application_logic"] = true
		return asset
	}
	model := secretsSprawlModel(
		custom("service", types.Process),
		custom("store", types.Datastore),
		custom("partner", types.ExternalEntity),
	)

	assert.ElementsMatch(t, []string{"service", "store"},
		keys(firedOn(generateScriptRisks(t, vulnerableOutdatedDependencyForReview, model))),
		"an external entity's dependencies are not ours to manage")
	assert.ElementsMatch(t, []string{"service", "store"},
		keys(firedOn(generateScriptRisks(t, osCommandInjectionForReview, model))))
}

func TestClusterAuditGapTakesTheHighestLikelihoodAndKeepsRuntimeIDsApart(t *testing.T) {
	quiet, exposed, clash := container("quiet"), container("exposed"), container("k8s")
	quiet.RAA, exposed.RAA = 30, 20
	exposed.Internet = true // the internet step lifts the less attractive container above the other
	model := secretsSprawlModel(quiet, exposed, clash)
	model.SharedRuntimes = map[string]*types.SharedRuntime{
		"k8s": {Id: "k8s", Title: "k8s", TechnicalAssetsRunning: []string{"quiet", "exposed"}},
	}

	risks, err := builtin.NewClusterControlPlaneAuditGapRule().GenerateRisks(model)
	assert.NoError(t, err)

	ids := map[string]*types.Risk{}
	for _, risk := range risks {
		ids[risk.SyntheticId] = risk
	}
	assert.Len(t, ids, 2, "a runtime and a lone container named alike must not share a synthetic id")
	runtime := ids["cluster-control-plane-audit-gap@shared-runtime:k8s"]
	if assert.NotNil(t, runtime) {
		assert.Equal(t, types.VeryLikely, runtime.ExploitationLikelihood,
			"the exposed container (RAA 20, internet +1: Very Likely) outranks the more attractive quiet one (RAA 30: Likely)")
	}
	assert.NotNil(t, ids["cluster-control-plane-audit-gap@k8s"], "the lone container keeps its own id")
}
