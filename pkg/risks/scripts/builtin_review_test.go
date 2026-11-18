package scripts

// Regressions from the 2026-11-18 independent review of the applied calibration.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threagile/threagile/pkg/risks/builtin"
	"github.com/threagile/threagile/pkg/types"
)

func TestMissingAuthenticationRatesTheTargetWhenTheLinkCarriesNoData(t *testing.T) {
	target := agencyAsset("target", "web-service-rest")
	target.Confidentiality, target.Integrity, target.Availability = types.Confidential, types.Critical, types.Important
	caller := agencyAsset("caller", "web-application", &types.CommunicationLink{
		Id: "caller>target", TargetId: "target", Protocol: types.HTTPS, Authentication: types.NoneAuthentication,
	})
	model := boundaryModel(map[string]string{}, caller, target)

	risks, err := builtin.NewMissingAuthenticationRule().GenerateRisks(model)
	require.NoError(t, err)
	require.Len(t, risks, 1)
	assert.Equal(t, types.Likely, risks[0].ExploitationLikelihood)
	assert.Equal(t, types.HighImpact, risks[0].ExploitationImpact,
		"no data on the link: rate on the confidential/critical target, not an empty link")
}

func TestWholeModelChecksKeepAFlatLikelihood(t *testing.T) {
	example := agencyAsset("example", "web-application")
	example.CustomDevelopedParts = true
	example.Internet = true
	example.RAA = 60
	example.CommunicationLinks = []*types.CommunicationLink{
		{Id: "example>store", TargetId: "store", Authorization: types.EndUserIdentityPropagation},
	}
	model := boundaryModel(map[string]string{}, example, agencyAsset("store", "database"))

	for name, rule := range map[string]types.RiskRule{
		"missing-build-infrastructure": builtin.NewMissingBuildInfrastructureRule(),
		"missing-identity-store":       builtin.NewMissingIdentityStoreRule(),
	} {
		risks, err := rule.GenerateRisks(model)
		require.NoError(t, err, name)
		require.NotEmpty(t, risks, name)
		assert.Equal(t, types.Unlikely, risks[0].ExploitationLikelihood,
			"%s: the example asset's RAA and exposure say nothing about a gap in the whole model", name)
		assert.Equal(t, types.LowImpact, risks[0].ExploitationImpact, name)
	}
}
