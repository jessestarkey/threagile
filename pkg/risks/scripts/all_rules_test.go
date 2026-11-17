package scripts

// Harness covering every embedded script rule at once. Per-rule behaviour (fires when it should,
// stays quiet when it shouldn't, likelihood steps) belongs in a per-rule test such as
// hardcoded_credentials_secrets_sprawl_test.go; this file only guarantees that no rule is
// broken, incomplete, or silently dead.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

// Rules that legitimately cannot fire on the kitchen-sink model below. Every entry needs a reason;
// the test fails if an entry is listed here but does fire (stale) or isn't a real rule id.
var scriptRulesNotExpectedToFireOnKitchenSink = map[string]string{}

func loadAllScriptRules(t *testing.T) map[string]types.RiskRule {
	t.Helper()
	rules, err := risks.GetScriptRiskRules()
	require.NoError(t, err)
	result := make(map[string]types.RiskRule, len(rules))
	for id, rule := range rules {
		result[id] = rule
	}
	return result
}

func scriptRuleFileIds(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	ids := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".yaml" {
			ids = append(ids, strings.TrimSuffix(entry.Name(), ".yaml"))
		}
	}
	sort.Strings(ids)
	return ids
}

func TestEveryScriptRuleLoadsWithCompleteMetadata(t *testing.T) {
	rules := loadAllScriptRules(t)
	fileIds := scriptRuleFileIds(t)

	require.Len(t, rules, len(fileIds), "every .yaml file must load as exactly one rule")

	for _, id := range fileIds {
		t.Run(id, func(t *testing.T) {
			rule, ok := rules[id]
			require.True(t, ok, "rule id must match its file name")

			category := rule.Category()
			assert.Equal(t, id, category.ID)
			assert.NotEmpty(t, category.Title, "title")
			assert.NotEmpty(t, category.Description, "description")
			assert.NotEmpty(t, category.Impact, "impact")
			assert.NotEmpty(t, category.Action, "action")
			assert.NotEmpty(t, category.Mitigation, "mitigation")
			assert.NotEmpty(t, category.Check, "check")
			assert.NotEmpty(t, category.DetectionLogic, "detection_logic")
			assert.NotEmpty(t, category.RiskAssessment, "risk_assessment")
			assert.NotEmpty(t, category.FalsePositives, "false_positives")
			assert.Greater(t, category.CWE, 0, "cwe")
		})
	}
}

// kitchenSinkModel holds, for every technology in the catalogue, one in-scope process on a
// container and one in-scope datastore on physical hardware, plus a few assets for rules gated on
// machine, multi-tenancy or link facts. Everything is rated at the top of every CIA scale, so a
// rule that matches anything here should fire.
func kitchenSinkModel(t *testing.T) *types.Model {
	t.Helper()
	technologies := make(types.TechnologyMap)
	require.NoError(t, technologies.LoadDefault())
	technologies.PropagateAttributes()

	model := &types.Model{
		DataAssets: map[string]*types.DataAsset{
			"data": {
				Id:              "data",
				Title:           "Data",
				Confidentiality: types.StrictlyConfidential,
				Integrity:       types.MissionCritical,
				Availability:    types.MissionCritical,
			},
		},
		TechnicalAssets: map[string]*types.TechnicalAsset{},
	}

	add := func(id string, technology string, machine types.TechnicalAssetMachine, assetType types.TechnicalAssetType) *types.TechnicalAsset {
		tech := technologies.Get(technology)
		require.NotNil(t, tech, "technology %q", technology)
		asset := &types.TechnicalAsset{
			Id:                   id,
			Title:                id,
			Type:                 assetType,
			Machine:              machine,
			Technologies:         types.TechnologyList{tech},
			CustomDevelopedParts: true,
			MultiTenant:          true,
			Confidentiality:      types.StrictlyConfidential,
			Integrity:            types.MissionCritical,
			Availability:         types.MissionCritical,
			RAA:                  50,
			DataAssetsProcessed:  []string{"data"},
			DataAssetsStored:     []string{"data"},
		}
		model.TechnicalAssets[id] = asset
		return asset
	}

	for name := range technologies {
		add(name+"-container", name, types.Container, types.Process)
		add(name+"-physical", name, types.Physical, types.Datastore)
	}
	add("vm", "web-application", types.Virtual, types.Process)
	add("function", "web-application", types.Serverless, types.Process)

	// A static-secret link, for rules that read outgoing-link authentication.
	app := model.TechnicalAssets["web-application-container"]
	require.NotNil(t, app)
	app.CommunicationLinks = append(app.CommunicationLinks, &types.CommunicationLink{
		Id:             "app>database",
		SourceId:       app.Id,
		TargetId:       "database-physical",
		Authentication: types.Credentials,
	})

	// A writable tool link from an agent, for rules that read link targets and readonly.
	agent := model.TechnicalAssets["ai-agent-orchestrator-container"]
	require.NotNil(t, agent)
	agent.CommunicationLinks = append(agent.CommunicationLinks, &types.CommunicationLink{
		Id:       "agent>database",
		SourceId: agent.Id,
		TargetId: "database-physical",
	})

	// An agent-to-agent link under the agent's own identity over an unencrypted protocol, for
	// rules that read delegation, authorization, and protocol.
	agent.CommunicationLinks = append(agent.CommunicationLinks, &types.CommunicationLink{
		Id:             "agent>multi-agent-gateway",
		SourceId:       agent.Id,
		TargetId:       "ai-multi-agent-gateway-container",
		Authentication: types.Token,
		Authorization:  types.TechnicalUser,
		Protocol:       types.HTTP,
	})

	return model
}

func TestEveryScriptRuleRunsAndFiresOnKitchenSinkModel(t *testing.T) {
	rules := loadAllScriptRules(t)
	model := kitchenSinkModel(t)

	for id := range scriptRulesNotExpectedToFireOnKitchenSink {
		_, ok := rules[id]
		assert.True(t, ok, "allowlist entry %q is not a script rule", id)
	}

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			generated, err := rules[id].GenerateRisks(model)
			require.NoError(t, err, "rule must run without a script error")

			reason, allowed := scriptRulesNotExpectedToFireOnKitchenSink[id]
			if allowed {
				assert.Empty(t, generated, "allowlisted as not firing (%s) but fired: remove the entry", reason)
				return
			}
			assert.NotEmpty(t, generated, "rule fired on nothing in the kitchen-sink model: check its match conditions for a misspelled attribute or field")
		})
	}
}
