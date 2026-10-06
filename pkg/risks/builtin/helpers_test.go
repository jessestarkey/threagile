package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/threagile/threagile/pkg/types"
)

func Test_IsAcrossTrustBoundaryNetworkOnly_EmptyDataReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_NoSourceIdReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_SourceIdIsNotNetworkBoundaryReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"trust-boundary": {
				Id:                    "trust-boundary",
				TrustBoundariesNested: []string{"trust-boundary-2"},
			},
		},
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": {
				Id:   "trust-boundary",
				Type: types.ExecutionEnvironment,
			},
			"target": {
				Id:   "trust-boundary-2",
				Type: types.ExecutionEnvironment,
			},
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_NoTargetIdReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": {
				Id: "trust-boundary",
			},
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_TargetIdIsNotNetworkBoundaryReturnFalse(t *testing.T) {
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": {
				Id: "trust-boundary",
			},
			"target": {
				Id:   "trust-boundary",
				Type: types.ExecutionEnvironment,
			},
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.False(t, result)
}

func Test_IsAcrossTrustBoundaryNetworkOnly_Compare(t *testing.T) {
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	anotherTrustBoundary := types.TrustBoundary{
		Id: "another-trust-boundary",
	}
	cl := &types.CommunicationLink{
		SourceId: "source",
		TargetId: "target",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"source": &trustBoundary,
			"target": &anotherTrustBoundary,
		},
	}

	result := isAcrossTrustBoundaryNetworkOnly(parsedModel, cl)

	assert.True(t, result)
}

func Test_isSameExecutionEnvironment_EmptyDataReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{}
	parsedModel := &types.Model{}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameExecutionEnvironemnt_NoTrustBoundaryOfMyAssetReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"other-asset": {},
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")
	assert.False(t, result)
}

func Test_isSameExecutionEnvironment_NoTrustBoundaryOfOtherAssetReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset": {},
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameExecutionEnvironemnt_NoTrustBoundaryOfEitherAssetReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameExecutionEnvironment_TrustBoundariesAreDifferentReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id:   "trust-boundary",
		Type: types.ExecutionEnvironment,
	}
	otherTrustBoundary := types.TrustBoundary{
		Id:   "other-trust-boundary",
		Type: types.ExecutionEnvironment,
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &otherTrustBoundary,
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameExecutionEnvironment_TrustBoundariesAreSameReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id:   "trust-boundary",
		Type: types.ExecutionEnvironment,
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary,
		},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameExecutionEnvironment_TrustBoundariesAreNotBothExecutionEnvironmentReturnFalse(t *testing.T) {

	tests := []struct {
		name                        string
		assetTrustBoundaryType      types.TrustBoundaryType
		otherAssetTrustBoundaryType types.TrustBoundaryType
	}{
		{"ExecutionEnvironment, NetworkCloudProvider", types.ExecutionEnvironment, types.NetworkCloudProvider},
		{"NetworkCloudProvider, ExecutionEnvironment", types.NetworkCloudProvider, types.ExecutionEnvironment},
		{"NetworkCloudProvider, NetworkCloudProvider", types.NetworkCloudProvider, types.NetworkCloudProvider},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ta := &types.TechnicalAsset{
				Id: "asset",
			}
			trustBoundary := types.TrustBoundary{
				Id:   "trust-boundary",
				Type: tt.assetTrustBoundaryType,
			}
			anotherTrustBoundary := types.TrustBoundary{
				Id:   "other-trust-boundary",
				Type: tt.otherAssetTrustBoundaryType,
			}
			parsedModel := &types.Model{
				DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
					"asset":       &trustBoundary,
					"other-asset": &anotherTrustBoundary,
				},
			}

			result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

			assert.False(t, result)
		})
	}
}

func Test_isSameTrustBoundaryNetworkOnly_EmptyDataReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{}
	parsedModel := &types.Model{}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_NoTrustBoundaryOfMyAssetReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"other-asset": {},
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_NoTrustBoundaryOfOtherAssetReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset": {},
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameExecutionEnvironemntNetworkOnly_NoTrustBoundaryOfEitherAssetReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{},
	}

	result := isSameExecutionEnvironment(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreDifferentReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	otherTrustBoundary := types.TrustBoundary{
		Id: "other-trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &otherTrustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreSameReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_IsNetworkBoundaryTrustBoundariesAreDifferentButParentIsSameReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parentTrustBoundary := types.TrustBoundary{
		Id:                    "parent-trust-boundary",
		TrustBoundariesNested: []string{"trust-boundary", "other-trust-boundary"},
	}
	trustBoundary := types.TrustBoundary{
		Id:   "trust-boundary",
		Type: types.NetworkCloudProvider,
	}
	otherTrustBoundary := types.TrustBoundary{
		Id:   "other-trust-boundary",
		Type: types.NetworkCloudProvider,
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &otherTrustBoundary,
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"trust-boundary":        &trustBoundary,
			"other-trust-boundary":  &otherTrustBoundary,
			"parent-trust-boundary": &parentTrustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_TrustBoundariesAreDifferentButParentIsDifferentReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	parentTrustBoundary := types.TrustBoundary{
		Id:                    "parent-trust-boundary",
		TrustBoundariesNested: []string{"trust-boundary"},
	}
	trustBoundary := types.TrustBoundary{
		Id: "trust-boundary",
	}
	otherTrustBoundary := types.TrustBoundary{
		Id: "other-trust-boundary",
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &otherTrustBoundary,
		},
		TrustBoundaries: map[string]*types.TrustBoundary{
			"trust-boundary":        &trustBoundary,
			"other-trust-boundary":  &otherTrustBoundary,
			"parent-trust-boundary": &parentTrustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_NotNetworkBoundaryReturnTrue(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id:   "trust-boundary",
		Type: types.ExecutionEnvironment,
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.True(t, result)
}

func Test_isSameTrustBoundaryNetworkOnly_DifferentNotNetworkBoundaryReturnFalse(t *testing.T) {
	ta := &types.TechnicalAsset{
		Id: "asset",
	}
	trustBoundary := types.TrustBoundary{
		Id:                    "trust-boundary",
		Type:                  types.ExecutionEnvironment,
		TechnicalAssetsInside: []string{"asset"},
	}
	trustBoundary2 := types.TrustBoundary{
		Id:                    "trust-boundary-2",
		TechnicalAssetsInside: []string{"other-asset"},
	}
	parsedModel := &types.Model{
		DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
			"asset":       &trustBoundary,
			"other-asset": &trustBoundary2,
		},
	}

	result := isSameTrustBoundaryNetworkOnly(parsedModel, ta, "other-asset")

	assert.False(t, result)
}

func Test_contains(t *testing.T) {
	tests := []struct {
		name     string
		as       []string
		b        string
		expected bool
	}{
		{"as null", nil, "foo", false},
		{"no match", []string{"foo", "bar"}, "bat", false},
		{"match", []string{"foo", "bar"}, "foo", true},
		{"no match different case", []string{"foo", "bar"}, "FOO", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := contains(test.as, test.b)
			assert.Equal(t, test.expected, result)
		})
	}
}

func Test_containsCaseInsensitiveAny(t *testing.T) {
	tests := []struct {
		name     string
		as       []string
		bs       []string
		expected bool
	}{
		{"as null, bs null", nil, nil, false},
		{"as null, bs not null", nil, []string{"foo", "bar"}, false},
		{"as not null, bs null", []string{"foo", "bar"}, nil, false},
		{"no match", []string{"foo", "bar"}, []string{"bat", "baz"}, false},
		{"match same case", []string{"foo", "bar"}, []string{"bat", "foo"}, true},
		{"match different case", []string{"FOO", "bar"}, []string{"bat", "foo"}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := containsCaseInsensitiveAny(test.as, test.bs...)
			assert.Equal(t, test.expected, result)
		})
	}
}

func Test_computeLikelihood(t *testing.T) {
	tests := []struct {
		name     string
		baseline types.RiskExploitationLikelihood
		raa      float64
		internet bool
		tags     []string
		expected types.RiskExploitationLikelihood
	}{
		{"mid RAA, not reachable, no change", types.Likely, 20, false, nil, types.Likely},
		{"low RAA pulls down a notch", types.Likely, 14.9, false, nil, types.PossibleLikelihood},
		{"mid RAA, no change", types.Likely, 15, false, nil, types.Likely},
		{"mid RAA, no change at upper edge", types.Likely, 39.9, false, nil, types.Likely},
		{"high RAA pushes up a notch", types.Likely, 40, false, nil, types.VeryLikely},
		{"internet field pushes up a notch", types.Likely, 20, true, nil, types.VeryLikely},
		{"net:internet-reachable tag pushes up a notch", types.Likely, 20, false, []string{"net:internet-reachable"}, types.VeryLikely},
		{"high RAA and internet together still clamp at VeryLikely", types.Likely, 50, true, nil, types.VeryLikely},
		{"low RAA and internet cancel out", types.Likely, 10, true, nil, types.Likely},
		{"clamps at Unlikely floor", types.Unlikely, 10, false, nil, types.Unlikely},
		{"clamps at VeryLikely ceiling", types.VeryLikely, 50, true, nil, types.VeryLikely},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ta := &types.TechnicalAsset{RAA: test.raa, Internet: test.internet, Tags: test.tags}
			result := computeLikelihood(test.baseline, ta)
			assert.Equal(t, test.expected, result)
		})
	}
}

func Test_computeImpact(t *testing.T) {
	tests := []struct {
		name         string
		baseline     types.RiskExploitationImpact
		stride       types.STRIDE
		confidential types.Confidentiality
		integrity    types.Criticality
		availability types.Criticality
		criticality  types.Criticality
		expected     types.RiskExploitationImpact
	}{
		{"mid rank, no change", types.MediumImpact, types.DenialOfService, types.Restricted, types.Important, types.Important, types.Archive, types.MediumImpact},
		{"low availability rank pulls DoS down despite high confidentiality", types.MediumImpact, types.DenialOfService, types.StrictlyConfidential, types.MissionCritical, types.Archive, types.Archive, types.LowImpact},
		{"high confidentiality rank pushes information-disclosure up", types.MediumImpact, types.InformationDisclosure, types.Confidential, types.Archive, types.Archive, types.Archive, types.HighImpact},
		{"elevation-of-privilege falls back to max(C,I,A)", types.MediumImpact, types.ElevationOfPrivilege, types.Public, types.MissionCritical, types.Archive, types.Archive, types.HighImpact},
		{"gated criticality bump fills the gap when CIA delta didn't earn it", types.MediumImpact, types.DenialOfService, types.Restricted, types.Important, types.Important, types.MissionCritical, types.HighImpact},
		{"gated criticality bump withheld when CIA delta already earned it", types.MediumImpact, types.DenialOfService, types.Restricted, types.Important, types.MissionCritical, types.MissionCritical, types.HighImpact},
		{"clamps at LowImpact floor", types.LowImpact, types.DenialOfService, types.Public, types.Archive, types.Archive, types.Archive, types.LowImpact},
		{"clamps at VeryHighImpact ceiling", types.VeryHighImpact, types.InformationDisclosure, types.StrictlyConfidential, types.Archive, types.Archive, types.MissionCritical, types.VeryHighImpact},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ta := &types.TechnicalAsset{
				Confidentiality: test.confidential,
				Integrity:       test.integrity,
				Availability:    test.availability,
			}
			model := &types.Model{BusinessCriticality: test.criticality}
			result := computeImpact(test.baseline, test.stride, ta, model)
			assert.Equal(t, test.expected, result)
		})
	}
}
