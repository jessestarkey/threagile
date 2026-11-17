package scripts

// Per-rule tests for the agentic AI rules of the rework plan (#8-#12). Helpers come from
// ai_excessive_agency_tool_misuse_test.go (agencyAsset, agencyLink) and
// hardcoded_credentials_secrets_sprawl_test.go (secretsSprawlModel).

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/risks/script"
	"github.com/threagile/threagile/pkg/types"
)

//go:embed ai-agent-identity-privilege-abuse.yaml
var aiAgentIdentityPrivilegeAbuse string

func generateScriptRisks(t *testing.T, ruleYAML string, model *types.Model) []*types.Risk {
	t.Helper()
	rule, err := new(script.RiskRule).Init().ParseFromData([]byte(ruleYAML))
	require.NoError(t, err)
	risks, err := rule.GenerateRisks(model)
	require.NoError(t, err)
	return risks
}

func identityLink(id, target string, authentication types.Authentication, authorization types.Authorization) *types.CommunicationLink {
	return &types.CommunicationLink{Id: id, TargetId: target, Authentication: authentication, Authorization: authorization}
}

// --- #8 Agent Identity and Privilege Abuse ---

func TestAgentIdentityFiresOnServiceIdentityLinks(t *testing.T) {
	for _, technology := range []string{"ai-agent-orchestrator", "ai-tool-server", "ai-gateway", "ai-multi-agent-gateway"} {
		for _, authorization := range []types.Authorization{types.TechnicalUser, types.NoneAuthorization} {
			t.Run(technology+"/"+authorization.String(), func(t *testing.T) {
				model := secretsSprawlModel(
					agencyAsset("agent", technology, identityLink("agent>db", "db", types.Token, authorization)),
					agencyAsset("db", "database"),
				)

				risks := generateScriptRisks(t, aiAgentIdentityPrivilegeAbuse, model)

				require.Len(t, risks, 1)
				assert.Equal(t, "agent", risks[0].MostRelevantTechnicalAssetId)
				assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
				assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
			})
		}
	}
}

func TestAgentIdentityIgnoresPropagatedOrUnauthenticatedLinks(t *testing.T) {
	model := secretsSprawlModel(
		agencyAsset("agent", "ai-agent-orchestrator",
			identityLink("agent>db", "db", types.Token, types.EndUserIdentityPropagation),
			identityLink("agent>open", "open", types.NoneAuthentication, types.TechnicalUser)),
		agencyAsset("db", "database"),
		agencyAsset("open", "web-server"),
	)

	assert.Empty(t, generateScriptRisks(t, aiAgentIdentityPrivilegeAbuse, model))
}

func TestAgentIdentityIgnoresNonAgentsAndOutOfScope(t *testing.T) {
	outOfScope := agencyAsset("agent", "ai-agent-orchestrator", identityLink("agent>db", "db", types.Token, types.TechnicalUser))
	outOfScope.OutOfScope = true
	model := secretsSprawlModel(
		outOfScope,
		agencyAsset("app", "web-application", identityLink("app>db", "db", types.Token, types.TechnicalUser)),
		agencyAsset("db", "database"),
	)

	assert.Empty(t, generateScriptRisks(t, aiAgentIdentityPrivilegeAbuse, model))
}

func TestAgentIdentityImpactComesFromTargetsReachedAsItself(t *testing.T) {
	critical := agencyAsset("db", "database")
	critical.Confidentiality = types.StrictlyConfidential
	propagatedOnly := secretsSprawlModel(
		agencyAsset("agent", "ai-agent-orchestrator",
			identityLink("agent>db", "db", types.Token, types.EndUserIdentityPropagation),
			identityLink("agent>log", "log", types.Token, types.TechnicalUser)),
		critical,
		agencyAsset("log", "file-server"),
	)
	asItself := secretsSprawlModel(
		agencyAsset("agent", "ai-agent-orchestrator", identityLink("agent>db", "db", types.Token, types.TechnicalUser)),
		critical,
	)

	risks := generateScriptRisks(t, aiAgentIdentityPrivilegeAbuse, propagatedOnly)
	require.Len(t, risks, 1)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact, "critical target reached only with propagated identity")

	risks = generateScriptRisks(t, aiAgentIdentityPrivilegeAbuse, asItself)
	require.Len(t, risks, 1)
	assert.Equal(t, types.VeryHighImpact, risks[0].ExploitationImpact)
}

// --- #9 Insecure Inter-Agent Communication ---

//go:embed ai-insecure-inter-agent-communication.yaml
var aiInsecureInterAgentCommunication string

func agentLink(target string, authentication types.Authentication, protocol types.Protocol) *types.CommunicationLink {
	return &types.CommunicationLink{Id: "a>" + target, TargetId: target, Authentication: authentication, Protocol: protocol}
}

// interAgentModel puts "a" (an orchestrator with the given link) and "b" (a multi-agent gateway)
// into the named trust boundaries; an empty name leaves that asset outside any boundary.
func interAgentModel(link *types.CommunicationLink, boundaryA, boundaryB string) *types.Model {
	model := secretsSprawlModel(
		agencyAsset("a", "ai-agent-orchestrator", link),
		agencyAsset("b", "ai-multi-agent-gateway"),
		agencyAsset("llm", "ai-llm-endpoint"),
	)
	model.DirectContainingTrustBoundaryMappedByTechnicalAssetId = map[string]*types.TrustBoundary{}
	for assetId, boundary := range map[string]string{"a": boundaryA, "b": boundaryB} {
		if boundary != "" {
			model.DirectContainingTrustBoundaryMappedByTechnicalAssetId[assetId] = &types.TrustBoundary{Id: boundary, Title: boundary}
		}
	}
	return model
}

func TestInterAgentCommunicationFiringConditions(t *testing.T) {
	tests := []struct {
		name                 string
		link                 *types.CommunicationLink
		boundaryA, boundaryB string
		fires                bool
	}{
		{"same boundary, authenticated, encrypted", agentLink("b", types.Token, types.HTTPS), "zone", "zone", false},
		{"neither in a boundary, authenticated, encrypted", agentLink("b", types.Token, types.HTTPS), "", "", false},
		{"crosses a boundary", agentLink("b", types.Token, types.HTTPS), "zone", "other", true},
		{"one side outside any boundary", agentLink("b", types.Token, types.HTTPS), "zone", "", true},
		{"unauthenticated", agentLink("b", types.NoneAuthentication, types.HTTPS), "zone", "zone", true},
		{"unencrypted protocol", agentLink("b", types.Token, types.HTTP), "zone", "zone", true},
		{"insecure link to a non-agent target", agentLink("llm", types.NoneAuthentication, types.HTTP), "zone", "other", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			risks := generateScriptRisks(t, aiInsecureInterAgentCommunication, interAgentModel(test.link, test.boundaryA, test.boundaryB))

			if !test.fires {
				assert.Empty(t, risks)
				return
			}
			require.Len(t, risks, 1)
			assert.Equal(t, "a", risks[0].MostRelevantTechnicalAssetId)
			assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
		})
	}
}

func TestInterAgentCommunicationImpactFromReceivingAgentIntegrity(t *testing.T) {
	model := interAgentModel(agentLink("b", types.NoneAuthentication, types.HTTPS), "zone", "zone")
	model.TechnicalAssets["b"].Integrity = types.Critical

	risks := generateScriptRisks(t, aiInsecureInterAgentCommunication, model)

	require.Len(t, risks, 1)
	assert.Equal(t, types.VeryHighImpact, risks[0].ExploitationImpact)
}

// Regression: a link target rated at the zero value of every CIA scale (public / archive) has
// those fields dropped on re-serialization; reading them used to panic the script engine.
func TestLinkReadingRulesHandleZeroValueTargetRatings(t *testing.T) {
	zero := &types.TechnicalAsset{
		Id:              "zero",
		Title:           "zero",
		Technologies:    types.TechnologyList{{Name: "ai-multi-agent-gateway", Attributes: map[string]bool{"ai-multi-agent-gateway": true}}},
		Confidentiality: types.Public,
		Integrity:       types.Archive,
		Availability:    types.Archive,
	}
	for name, ruleYAML := range map[string]string{
		"ai-excessive-agency-tool-misuse":       aiExcessiveAgencyToolMisuse,
		"ai-agent-identity-privilege-abuse":     aiAgentIdentityPrivilegeAbuse,
		"ai-insecure-inter-agent-communication": aiInsecureInterAgentCommunication,
	} {
		t.Run(name, func(t *testing.T) {
			agent := agencyAsset("agent", "ai-agent-orchestrator",
				&types.CommunicationLink{Id: "agent>zero", TargetId: "zero", Authentication: types.Token, Authorization: types.TechnicalUser})
			agent.Confidentiality = types.Public
			agent.Integrity = types.Archive
			agent.Availability = types.Archive

			risks := generateScriptRisks(t, ruleYAML, secretsSprawlModel(agent, zero))

			require.Len(t, risks, 1)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
		})
	}
}

// --- #10 Cascading Agent Failures ---

//go:embed ai-cascading-agent-failures.yaml
var aiCascadingAgentFailures string

func TestCascadingAgentFailuresFiresOnlyOnAgentToAgentLinks(t *testing.T) {
	model := secretsSprawlModel(
		agencyAsset("planner", "ai-agent-orchestrator", agencyLink("planner>worker", "worker", true)),
		agencyAsset("worker", "ai-multi-agent-gateway", agencyLink("worker>llm", "llm", true)),
		agencyAsset("solo", "ai-agent-orchestrator", agencyLink("solo>llm", "llm", false), agencyLink("solo>tools", "tools", false)),
		agencyAsset("llm", "ai-llm-endpoint"),
		agencyAsset("tools", "ai-tool-server"),
	)

	risks := generateScriptRisks(t, aiCascadingAgentFailures, model)

	require.Len(t, risks, 1, "only the agent that hands work to another agent")
	assert.Equal(t, "planner", risks[0].MostRelevantTechnicalAssetId)
	assert.Equal(t, types.PossibleLikelihood, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact)
}

func TestCascadingAgentFailuresImpactFromChainAvailability(t *testing.T) {
	for availability, expected := range map[types.Criticality]types.RiskExploitationImpact{
		types.Operational:     types.LowImpact,
		types.Important:       types.MediumImpact,
		types.MissionCritical: types.HighImpact,
	} {
		worker := agencyAsset("worker", "ai-agent-orchestrator")
		worker.Availability = availability
		model := secretsSprawlModel(agencyAsset("planner", "ai-agent-orchestrator", agencyLink("planner>worker", "worker", true)), worker)

		risks := generateScriptRisks(t, aiCascadingAgentFailures, model)

		require.Len(t, risks, 1)
		assert.Equal(t, expected, risks[0].ExploitationImpact, "downstream availability %v", availability)
	}
}

// --- #11 Rogue Agent and Missing Kill Switch ---

//go:embed ai-rogue-agent-containment-gap.yaml
var aiRogueAgentContainmentGap string

func TestRogueAgentFiresOnAgentsAndModelsOnly(t *testing.T) {
	model := secretsSprawlModel(
		agencyAsset("agent", "ai-agent-orchestrator"),
		agencyAsset("llm", "ai-llm-endpoint"),
		agencyAsset("serving", "ai-model-serving"),
		agencyAsset("gateway", "ai-gateway"),
		agencyAsset("app", "web-application"),
	)

	fired := map[string]bool{}
	for _, risk := range generateScriptRisks(t, aiRogueAgentContainmentGap, model) {
		fired[risk.MostRelevantTechnicalAssetId] = true
	}

	assert.Equal(t, map[string]bool{"agent": true, "llm": true, "serving": true}, fired)
}

func TestRogueAgentLikelihoodStepsDownWhenMonitored(t *testing.T) {
	tests := []struct {
		raa       float64
		monitored bool
		expected  types.RiskExploitationLikelihood
	}{
		{5, false, types.PossibleLikelihood},
		{5, true, types.Unlikely},
		{30, false, types.Likely},
		{30, true, types.PossibleLikelihood},
		{60, false, types.VeryLikely},
		{60, true, types.Likely},
	}
	for _, test := range tests {
		agent := agencyAsset("agent", "ai-agent-orchestrator")
		agent.RAA = test.raa
		if test.monitored {
			agent.CommunicationLinks = []*types.CommunicationLink{agencyLink("agent>obs", "obs", false)}
		}
		model := secretsSprawlModel(agent, agencyAsset("obs", "ai-observability-stack"))

		risks := generateScriptRisks(t, aiRogueAgentContainmentGap, model)

		require.Len(t, risks, 1)
		assert.Equal(t, test.expected, risks[0].ExploitationLikelihood, "RAA %v, monitored %v", test.raa, test.monitored)
	}
}

// --- #12 AI Change Control Gap ---

//go:embed ai-change-control-gap.yaml
var aiChangeControlGap string

func TestChangeControlGapFiresOnPromptAndModelBearingAssets(t *testing.T) {
	critical := agencyAsset("llm", "ai-llm-endpoint")
	critical.Integrity = types.Critical
	outOfScope := agencyAsset("ignored", "ai-model-serving")
	outOfScope.OutOfScope = true
	model := secretsSprawlModel(
		critical,
		agencyAsset("serving", "ai-model-serving"),
		agencyAsset("rag", "ai-rag-pipeline"),
		agencyAsset("agent", "ai-agent-orchestrator"),
		agencyAsset("vectors", "ai-vector-store"),
		outOfScope,
	)

	impact := map[string]types.RiskExploitationImpact{}
	for _, risk := range generateScriptRisks(t, aiChangeControlGap, model) {
		impact[risk.MostRelevantTechnicalAssetId] = risk.ExploitationImpact
	}

	assert.Equal(t, map[string]types.RiskExploitationImpact{
		"llm":     types.HighImpact,
		"serving": types.LowImpact,
		"rag":     types.LowImpact,
		"agent":   types.LowImpact,
	}, impact)
}

// Review finding 1: an agent calling its own model (or monitoring) is not a tool action and does
// not act "as itself" against anything; an AI gateway holding its backends' credentials still does.
func TestAgentLinksToModelInfrastructureAreIgnored(t *testing.T) {
	model := secretsSprawlModel(
		agencyAsset("agent", "ai-agent-orchestrator",
			identityLink("agent>llm", "llm", types.Token, types.TechnicalUser),
			identityLink("agent>metrics", "metrics", types.Token, types.TechnicalUser),
			agencyLink("agent>kb", "kb", true)),
		agencyAsset("gateway", "ai-gateway", identityLink("gateway>llm", "llm", types.Token, types.TechnicalUser)),
		agencyAsset("llm", "ai-llm-endpoint"),
		withMonitoring(agencyAsset("metrics", "monitoring")),
		agencyAsset("kb", "database"),
	)

	assert.Empty(t, generateScriptRisks(t, aiExcessiveAgencyToolMisuse, model), "only the model, telemetry and a read-only tool")
	identity := firedOn(generateScriptRisks(t, aiAgentIdentityPrivilegeAbuse, model))
	assert.ElementsMatch(t, []string{"gateway"}, keys(identity), "the gateway's backend credentials still count")
}

func withMonitoring(asset *types.TechnicalAsset) *types.TechnicalAsset {
	asset.Technologies[0].Attributes["monitoring"] = true
	return asset
}
