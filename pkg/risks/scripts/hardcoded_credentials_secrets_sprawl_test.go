package scripts

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/risks/script"
	"github.com/threagile/threagile/pkg/types"
)

//go:embed hardcoded-credentials-secrets-sprawl.yaml
var hardcodedCredentialsSecretsSprawl string

func loadHardcodedCredentialsSecretsSprawlRule(t *testing.T) types.RiskRule {
	t.Helper()
	rule, err := new(script.RiskRule).Init().ParseFromData([]byte(hardcodedCredentialsSecretsSprawl))
	require.NoError(t, err)
	return rule
}

func secretsSprawlTechnology(name string, attributes map[string]bool) types.TechnologyList {
	return types.TechnologyList{{Name: name, Attributes: attributes}}
}

func secretsSprawlApp(raa float64, links ...*types.CommunicationLink) *types.TechnicalAsset {
	for _, link := range links {
		link.SourceId = "app"
	}
	return &types.TechnicalAsset{
		Id:                 "app",
		Title:              "App",
		Technologies:       secretsSprawlTechnology("web-application", map[string]bool{}),
		Confidentiality:    types.Confidential,
		RAA:                raa,
		CommunicationLinks: links,
	}
}

func secretsSprawlTarget(id string, technology string, attributes map[string]bool) *types.TechnicalAsset {
	return &types.TechnicalAsset{
		Id:           id,
		Title:        id,
		Technologies: secretsSprawlTechnology(technology, attributes),
	}
}

func secretsSprawlLink(id string, target string, authentication types.Authentication) *types.CommunicationLink {
	return &types.CommunicationLink{Id: id, TargetId: target, Authentication: authentication}
}

func secretsSprawlModel(assets ...*types.TechnicalAsset) *types.Model {
	model := &types.Model{TechnicalAssets: map[string]*types.TechnicalAsset{}}
	for _, asset := range assets {
		model.TechnicalAssets[asset.Id] = asset
	}
	return model
}

func generateSecretsSprawlRisks(t *testing.T, model *types.Model) []*types.Risk {
	t.Helper()
	risks, err := loadHardcodedCredentialsSecretsSprawlRule(t).GenerateRisks(model)
	require.NoError(t, err)
	return risks
}

func TestHardcodedCredentialsFiresOnStaticSecretAuthentication(t *testing.T) {
	for _, authentication := range []types.Authentication{types.Credentials, types.ClientCertificate} {
		t.Run(authentication.String(), func(t *testing.T) {
			model := secretsSprawlModel(
				secretsSprawlApp(50, secretsSprawlLink("app>db", "db", authentication)),
				secretsSprawlTarget("db", "database", map[string]bool{}),
			)

			risks := generateSecretsSprawlRisks(t, model)

			require.Len(t, risks, 1)
			assert.Equal(t, "app", risks[0].MostRelevantTechnicalAssetId)
			assert.Equal(t, types.VeryLikely, risks[0].ExploitationLikelihood)
			assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact)
		})
	}
}

func TestHardcodedCredentialsIgnoresIssuedOrAbsentSecrets(t *testing.T) {
	for _, authentication := range []types.Authentication{
		types.NoneAuthentication, types.SessionId, types.Token, types.TwoFactor, types.Externalized,
	} {
		t.Run(authentication.String(), func(t *testing.T) {
			model := secretsSprawlModel(
				secretsSprawlApp(50, secretsSprawlLink("app>db", "db", authentication)),
				secretsSprawlTarget("db", "database", map[string]bool{}),
			)

			assert.Empty(t, generateSecretsSprawlRisks(t, model))
		})
	}
}

func TestHardcodedCredentialsIgnoresAssetWithoutLinks(t *testing.T) {
	assert.Empty(t, generateSecretsSprawlRisks(t, secretsSprawlModel(secretsSprawlApp(50))))
}

func TestHardcodedCredentialsIgnoresOutOfScopeAsset(t *testing.T) {
	app := secretsSprawlApp(50, secretsSprawlLink("app>db", "db", types.Credentials))
	app.OutOfScope = true
	model := secretsSprawlModel(app, secretsSprawlTarget("db", "database", map[string]bool{}))

	assert.Empty(t, generateSecretsSprawlRisks(t, model))
}

func TestHardcodedCredentialsIgnoresVaultAsset(t *testing.T) {
	vault := secretsSprawlApp(50, secretsSprawlLink("vault>hsm", "hsm", types.ClientCertificate))
	vault.Technologies = secretsSprawlTechnology("vault", map[string]bool{"vault": true})
	model := secretsSprawlModel(vault, secretsSprawlTarget("hsm", "hsm", map[string]bool{}))

	assert.Empty(t, generateSecretsSprawlRisks(t, model))
}

func TestHardcodedCredentialsLikelihoodStepsDownForVaultLinkAndLowRAA(t *testing.T) {
	tests := []struct {
		name     string
		raa      float64
		useVault bool
		expected types.RiskExploitationLikelihood
	}{
		{"no vault, normal RAA", 50, false, types.VeryLikely},
		{"no vault, low RAA", 5, false, types.PossibleLikelihood},
		{"vault, normal RAA", 50, true, types.Likely},
		{"vault, low RAA", 5, true, types.Unlikely},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			links := []*types.CommunicationLink{secretsSprawlLink("app>db", "db", types.Credentials)}
			if test.useVault {
				links = append(links, secretsSprawlLink("app>vault", "vault", types.Token))
			}
			model := secretsSprawlModel(
				secretsSprawlApp(test.raa, links...),
				secretsSprawlTarget("db", "database", map[string]bool{}),
				secretsSprawlTarget("vault", "vault", map[string]bool{"vault": true}),
			)

			risks := generateSecretsSprawlRisks(t, model)

			require.Len(t, risks, 1)
			assert.Equal(t, test.expected, risks[0].ExploitationLikelihood)
		})
	}
}
