package builtin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

func TestUnguardedDirectDatastoreAccessRuleGenerateRisksEmptyModelNotRisksCreated(t *testing.T) {
	rule := NewUnguardedDirectDatastoreAccessRule()

	risks, err := rule.GenerateRisks(&types.Model{})

	assert.Nil(t, err)
	assert.Empty(t, risks)
}

type UnguardedDirectDatastoreAccessRuleTest struct {
	outOfScope      bool
	isIdentityStore bool
	isFileServer    bool
	assetType       types.TechnicalAssetType
	raa             float64

	isSourceIdentityProvider bool

	isAcrossTrustBoundary            bool
	isSharingSameParentTrustBoundary bool

	protocol types.Protocol
	usage    types.Usage

	confidentiality types.Confidentiality
	integrity       types.Criticality

	riskCreated    bool
	expectedImpact types.RiskExploitationImpact
}

func TestUnguardedDirectDatastoreAccessRuleRuleGenerateRisks(t *testing.T) {
	testCases := map[string]UnguardedDirectDatastoreAccessRuleTest{
		"out of scope": {
			outOfScope: true,
			assetType:  types.Datastore,

			riskCreated: false,
		},
		"no data store": {
			outOfScope: false,
			assetType:  types.ExternalEntity,

			riskCreated: false,
		},
		"identity store to identity provider is ok": {
			outOfScope:               false,
			assetType:                types.Datastore,
			isSourceIdentityProvider: true,
			isIdentityStore:          true,
		},
		"no risk when data store is not critical": {
			outOfScope:      false,
			assetType:       types.Datastore,
			confidentiality: types.Restricted,
			integrity:       types.Operational,
		},
		"not across trust boundary network": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            false,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     false,
			protocol:                         types.HTTP,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated: false,
		},
		"sharing same parent trust boundary": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: true,
			usage:                            types.Business,
			isFileServer:                     false,
			protocol:                         types.HTTP,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated: false,
		},
		"devops usage": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.DevOps,
			isFileServer:                     false,
			protocol:                         types.HTTP,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated: false,
		},
		"file server access via ftp": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     true,
			protocol:                         types.FTP,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated: false,
		},
		"file server access via ftp (FTPS)": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     true,
			protocol:                         types.FTPS,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated: false,
		},
		"file server access via ftp (SFTP)": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     true,
			protocol:                         types.SFTP,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated: false,
		},
		"low impact": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     false,
			protocol:                         types.HTTP,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated:    true,
			expectedImpact: types.LowImpact,
		},
		"high raa no longer bumps impact": {
			// RAA was moved from an Impact bump to a Likelihood delta (see the comment in
			// unguarded_direct_datastore_access_rule.go's createRisk()) -- see
			// TestUnguardedDirectDatastoreAccessRuleRaaAffectsLikelihoodNotImpact below for the
			// Likelihood-side effect.
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     false,
			protocol:                         types.HTTP,
			raa:                              50,

			confidentiality: types.Confidential,
			integrity:       types.Critical,

			riskCreated:    true,
			expectedImpact: types.LowImpact,
		},
		"strict confidentiality medium impact": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     false,
			protocol:                         types.HTTP,

			confidentiality: types.StrictlyConfidential,
			integrity:       types.Critical,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
		"mission critical integrity medium impact": {
			outOfScope: false,
			assetType:  types.Datastore,

			isAcrossTrustBoundary:            true,
			isSharingSameParentTrustBoundary: false,
			usage:                            types.Business,
			isFileServer:                     false,
			protocol:                         types.HTTP,

			confidentiality: types.Confidential,
			integrity:       types.MissionCritical,

			riskCreated:    true,
			expectedImpact: types.MediumImpact,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			rule := NewUnguardedDirectDatastoreAccessRule()
			tb1 := &types.TrustBoundary{
				Id:                    "tb1",
				Title:                 "First Trust Boundary",
				TechnicalAssetsInside: []string{"source", "target"},
				Type:                  types.NetworkCloudProvider,
			}
			tb2 := &types.TrustBoundary{
				Id:    "tb2",
				Title: "Second Trust Boundary",
				Type:  types.NetworkCloudProvider,
			}
			if testCase.isAcrossTrustBoundary {
				tb1.TechnicalAssetsInside = []string{"source"}
				tb2.TechnicalAssetsInside = []string{"target"}
			}
			directContainingTrustBoundaryMappedByTechnicalAssetId := map[string]*types.TrustBoundary{
				"source": tb1,
				"target": tb1,
			}
			if testCase.isAcrossTrustBoundary {
				directContainingTrustBoundaryMappedByTechnicalAssetId["target"] = tb2
			}

			tb3 := &types.TrustBoundary{
				Id:    "tb3",
				Title: "Sharing Trust Boundary",
				Type:  types.NetworkCloudProvider,
			}
			if testCase.isSharingSameParentTrustBoundary {
				tb3.TrustBoundariesNested = []string{"tb1", "tb2"}
			}
			risks, err := rule.GenerateRisks(&types.Model{
				TechnicalAssets: map[string]*types.TechnicalAsset{
					"source": {
						Id:    "source",
						Title: "Source Technical Asset",
						Technologies: types.TechnologyList{
							{
								Attributes: map[string]bool{
									types.IdentityProvider: testCase.isSourceIdentityProvider,
								},
							},
						},
					},
					"target": {
						Id:         "target",
						Title:      "Target Technical Asset",
						OutOfScope: testCase.outOfScope,
						Type:       testCase.assetType,
						RAA:        testCase.raa,
						CommunicationLinks: []*types.CommunicationLink{
							{
								Title:    "Test Communication Link",
								SourceId: "source",
								TargetId: "target",
								Protocol: testCase.protocol,
								Usage:    testCase.usage,
							},
						},
						Technologies: types.TechnologyList{
							{
								Attributes: map[string]bool{
									types.FileServer:      testCase.isFileServer,
									types.IsIdentityStore: testCase.isIdentityStore,
								},
							},
						},
						Confidentiality: testCase.confidentiality,
						Integrity:       testCase.integrity,
					},
				},
				IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
					"target": {
						{
							Title:    "Test Communication Link",
							SourceId: "source",
							TargetId: "target",
							Protocol: testCase.protocol,
							Usage:    testCase.usage,
						},
					},
				},
				TrustBoundaries: map[string]*types.TrustBoundary{
					"tb1": tb1,
					"tb2": tb2,
					"tb3": tb3,
				},
				DirectContainingTrustBoundaryMappedByTechnicalAssetId: directContainingTrustBoundaryMappedByTechnicalAssetId,
			})

			assert.Nil(t, err)
			if testCase.riskCreated {
				assert.NotEmpty(t, risks)
				assert.Equal(t, testCase.expectedImpact, risks[0].ExploitationImpact)
				expectedMessage := "<b>Unguarded Direct Datastore Access</b> of <b>Target Technical Asset</b> by <b>Source Technical Asset</b> via <b>Test Communication Link</b>"
				assert.Equal(t, risks[0].Title, expectedMessage)
			} else {
				assert.Empty(t, risks)
			}
		})
	}
}

func TestUnguardedDirectDatastoreAccessRuleRaaAffectsLikelihoodNotImpact(t *testing.T) {
	newModel := func(raa float64) *types.Model {
		return &types.Model{
			TechnicalAssets: map[string]*types.TechnicalAsset{
				"source": {
					Id:    "source",
					Title: "Source Technical Asset",
				},
				"target": {
					Id:              "target",
					Title:           "Target Technical Asset",
					Type:            types.Datastore,
					RAA:             raa,
					Confidentiality: types.Confidential,
					Integrity:       types.Critical,
					CommunicationLinks: []*types.CommunicationLink{
						{
							Title:    "Test Communication Link",
							SourceId: "source",
							TargetId: "target",
							Protocol: types.HTTP,
							Usage:    types.Business,
						},
					},
				},
			},
			IncomingTechnicalCommunicationLinksMappedByTargetId: map[string][]*types.CommunicationLink{
				"target": {
					{
						Title:    "Test Communication Link",
						SourceId: "source",
						TargetId: "target",
						Protocol: types.HTTP,
						Usage:    types.Business,
					},
				},
			},
			TrustBoundaries: map[string]*types.TrustBoundary{
				"tb1": {Id: "tb1", TechnicalAssetsInside: []string{"source"}, Type: types.NetworkCloudProvider},
				"tb2": {Id: "tb2", TechnicalAssetsInside: []string{"target"}, Type: types.NetworkCloudProvider},
			},
			DirectContainingTrustBoundaryMappedByTechnicalAssetId: map[string]*types.TrustBoundary{
				"source": {Id: "tb1", TechnicalAssetsInside: []string{"source"}, Type: types.NetworkCloudProvider},
				"target": {Id: "tb2", TechnicalAssetsInside: []string{"target"}, Type: types.NetworkCloudProvider},
			},
		}
	}
	rule := NewUnguardedDirectDatastoreAccessRule()

	lowRaaRisks, err := rule.GenerateRisks(newModel(10)) // below raaLikelihoodLowThreshold (15)
	assert.Nil(t, err)
	assert.Len(t, lowRaaRisks, 1)
	assert.Equal(t, types.PossibleLikelihood, lowRaaRisks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, lowRaaRisks[0].ExploitationImpact)

	highRaaRisks, err := rule.GenerateRisks(newModel(50)) // at or above raaLikelihoodThreshold (40)
	assert.Nil(t, err)
	assert.Len(t, highRaaRisks, 1)
	assert.Equal(t, types.VeryLikely, highRaaRisks[0].ExploitationLikelihood)
	assert.Equal(t, types.LowImpact, highRaaRisks[0].ExploitationImpact) // unchanged by RAA, unlike before this redesign
}

func TestIsSharingSameParentTrustBoundaryBothOutOfTrustBoundaryExpectTrue(t *testing.T) {
	input := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id: "tb1",
			},
			"tb2": {
				Id: "tb2",
			},
		},
	}
	left := &types.TechnicalAsset{
		Id: "ta1",
	}
	right := &types.TechnicalAsset{
		Id: "ta2",
	}
	assert.True(t, isSharingSameParentTrustBoundary(input, left, right))
}

func TestIsSharingSameParentTrustBoundaryLeftOutOfTrustBoundaryExpectFalse(t *testing.T) {
	input := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id: "tb1",
			},
			"tb2": {
				Id:                    "tb2",
				TechnicalAssetsInside: []string{"ta2"},
			},
		},
	}
	left := &types.TechnicalAsset{
		Id: "ta1",
	}
	right := &types.TechnicalAsset{
		Id: "ta2",
	}
	assert.False(t, isSharingSameParentTrustBoundary(input, left, right))
}

func TestIsSharingSameParentTrustBoundaryRightOutOfTrustBoundaryExpectFalse(t *testing.T) {
	input := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				TechnicalAssetsInside: []string{"ta1"},
			},
			"tb2": {
				Id: "tb2",
			},
		},
	}
	left := &types.TechnicalAsset{
		Id: "ta1",
	}
	right := &types.TechnicalAsset{
		Id: "ta2",
	}
	assert.False(t, isSharingSameParentTrustBoundary(input, left, right))
}

func TestIsSharingSameParentTrustBoundaryInDifferentTrustBoundariesExpectFalse(t *testing.T) {
	input := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				TechnicalAssetsInside: []string{"ta1"},
			},
			"tb2": {
				Id: "tb2",
			},
		},
	}
	left := &types.TechnicalAsset{
		Id: "ta1",
	}
	right := &types.TechnicalAsset{
		Id: "ta2",
	}
	assert.False(t, isSharingSameParentTrustBoundary(input, left, right))
}

func TestIsSharingSameParentTrustBoundarySameTrustBoundariesExpectTrue(t *testing.T) {
	input := &types.Model{
		TrustBoundaries: map[string]*types.TrustBoundary{
			"tb1": {
				Id:                    "tb1",
				TechnicalAssetsInside: []string{"ta1", "ta2"},
			},
		},
	}
	left := &types.TechnicalAsset{
		Id: "ta1",
	}
	right := &types.TechnicalAsset{
		Id: "ta2",
	}
	assert.True(t, isSharingSameParentTrustBoundary(input, left, right))
}
