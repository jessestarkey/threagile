package scripts

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/risks/script"
	"github.com/threagile/threagile/pkg/types"
)

//go:embed ai-excessive-agency-tool-misuse.yaml
var aiExcessiveAgencyToolMisuse string

func generateExcessiveAgencyRisks(t *testing.T, model *types.Model) []*types.Risk {
	t.Helper()
	rule, err := new(script.RiskRule).Init().ParseFromData([]byte(aiExcessiveAgencyToolMisuse))
	require.NoError(t, err)
	risks, err := rule.GenerateRisks(model)
	require.NoError(t, err)
	return risks
}

// agencyAsset builds an in-house process asset of the given technology, rated low on every CIA
// dimension unless overridden, with RAA 30 (mid band: baseline likelihood). Type is set explicitly:
// the zero value is external-entity, which exposure-reading rules treat as an outside caller.
func agencyAsset(id, technology string, links ...*types.CommunicationLink) *types.TechnicalAsset {
	for _, link := range links {
		link.SourceId = id
	}
	return &types.TechnicalAsset{
		Id:                 id,
		Title:              id,
		Type:               types.Process,
		Technologies:       types.TechnologyList{{Name: technology, Attributes: map[string]bool{technology: true}}},
		Confidentiality:    types.Internal,
		Integrity:          types.Operational,
		Availability:       types.Operational,
		RAA:                30,
		CommunicationLinks: links,
	}
}

func agencyLink(id, target string, readonly bool) *types.CommunicationLink {
	return &types.CommunicationLink{Id: id, TargetId: target, Readonly: readonly}
}

func TestExcessiveAgencyFiresOnAgentAndToolServerWithWritableLink(t *testing.T) {
	for _, technology := range []string{"ai-agent-orchestrator", "ai-tool-server"} {
		t.Run(technology, func(t *testing.T) {
			model := secretsSprawlModel(
				agencyAsset("agent", technology, agencyLink("agent>db", "db", false)),
				agencyAsset("db", "database"),
			)

			risks := generateExcessiveAgencyRisks(t, model)

			require.Len(t, risks, 1)
			assert.Equal(t, "agent", risks[0].MostRelevantTechnicalAssetId)
			assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
		})
	}
}

func TestExcessiveAgencyIgnoresAgentWithOnlyReadonlyLinks(t *testing.T) {
	model := secretsSprawlModel(
		agencyAsset("agent", "ai-agent-orchestrator",
			agencyLink("agent>db", "db", true), agencyLink("agent>search", "search", true)),
		agencyAsset("db", "database"),
		agencyAsset("search", "search-index"),
	)

	assert.Empty(t, generateExcessiveAgencyRisks(t, model))
}

func TestExcessiveAgencyIgnoresAgentWithoutLinks(t *testing.T) {
	assert.Empty(t, generateExcessiveAgencyRisks(t, secretsSprawlModel(agencyAsset("agent", "ai-agent-orchestrator"))))
}

func TestExcessiveAgencyIgnoresOtherTechnologies(t *testing.T) {
	model := secretsSprawlModel(
		agencyAsset("app", "web-application", agencyLink("app>db", "db", false)),
		agencyAsset("llm", "ai-llm-endpoint", agencyLink("llm>db", "db", false)),
		agencyAsset("db", "database"),
	)

	assert.Empty(t, generateExcessiveAgencyRisks(t, model))
}

func TestExcessiveAgencyIgnoresOutOfScopeAgent(t *testing.T) {
	agent := agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>db", "db", false))
	agent.OutOfScope = true

	assert.Empty(t, generateExcessiveAgencyRisks(t, secretsSprawlModel(agent, agencyAsset("db", "database"))))
}

func TestExcessiveAgencyImpactComesFromWhatWritableToolsReach(t *testing.T) {
	valuable := func() *types.TechnicalAsset {
		db := agencyAsset("db", "database")
		db.Integrity = types.Critical
		return db
	}

	tests := []struct {
		name     string
		model    *types.Model
		expected types.RiskExploitationImpact
	}{
		{
			"everything low-value",
			secretsSprawlModel(
				agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>db", "db", false)),
				agencyAsset("db", "database"),
			),
			types.LowImpact,
		},
		{
			"writable link reaches a critical-integrity asset",
			secretsSprawlModel(
				agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>db", "db", false)),
				valuable(),
			),
			types.HighImpact,
		},
		{
			"critical asset reachable only read-only does not raise impact",
			secretsSprawlModel(
				agencyAsset("agent", "ai-agent-orchestrator",
					agencyLink("agent>db", "db", true), agencyLink("agent>log", "log", false)),
				valuable(),
				agencyAsset("log", "file-server"),
			),
			types.LowImpact,
		},
		{
			"agent itself holds confidential data",
			func() *types.Model {
				agent := agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>db", "db", false))
				agent.Confidentiality = types.Confidential
				return secretsSprawlModel(agent, agencyAsset("db", "database"))
			}(),
			types.HighImpact,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			risks := generateExcessiveAgencyRisks(t, test.model)

			require.Len(t, risks, 1)
			assert.Equal(t, test.expected, risks[0].ExploitationImpact)
		})
	}
}

func TestExcessiveAgencyLikelihoodFollowsRAA(t *testing.T) {
	for raa, expected := range map[float64]types.RiskExploitationLikelihood{
		5:  types.PossibleLikelihood,
		30: types.Likely,
		60: types.VeryLikely,
	} {
		agent := agencyAsset("agent", "ai-agent-orchestrator", agencyLink("agent>db", "db", false))
		agent.RAA = raa
		risks := generateExcessiveAgencyRisks(t, secretsSprawlModel(agent, agencyAsset("db", "database")))

		require.Len(t, risks, 1)
		assert.Equal(t, expected, risks[0].ExploitationLikelihood, "RAA %v", raa)
	}
}
