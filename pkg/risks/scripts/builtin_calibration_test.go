package scripts

// Calibration check for the built-in Go rules, run on the same profile-T kitchen-sink model as
// the script rules (calibration_test.go), with every link carrying profile-T data and no asset
// internet-facing, so link-rated rules and the internet step are in their default state.
// Built-ins that need protocols, DevOps links or trust boundaries the kitchen sink doesn't model
// don't fire here; their unit tests cover them.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

// builtinCalibratedOnProfileT is generated from the approved calibration table.
var builtinCalibratedOnProfileT = map[string]calibratedRating{
	"cluster-control-plane-audit-gap": {types.Likely, types.MediumImpact},
	"accidental-secret-leak":                 {types.Likely, types.MediumImpact},
	"code-backdooring":                       {types.PossibleLikelihood, types.HighImpact},
	"container-platform-escape":              {types.Unlikely, types.VeryHighImpact},
	"cross-site-request-forgery":             {types.PossibleLikelihood, types.MediumImpact},
	"cross-site-scripting":                   {types.Likely, types.HighImpact},
	"dos-risky-access-across-trust-boundary": {types.PossibleLikelihood, types.MediumImpact},
	"ldap-injection":                         {types.PossibleLikelihood, types.HighImpact},
	"missing-authentication":                 {types.Likely, types.HighImpact},
	"missing-authentication-second-factor":   {types.Likely, types.HighImpact},
	"missing-build-infrastructure":           {types.Unlikely, types.LowImpact},
	"missing-cloud-hardening":                {types.PossibleLikelihood, types.MediumImpact},
	"missing-file-validation":                {types.PossibleLikelihood, types.HighImpact},
	"missing-hardening":                      {types.PossibleLikelihood, types.MediumImpact},
	"missing-identity-propagation":           {types.PossibleLikelihood, types.MediumImpact},
	"missing-identity-provider-isolation":    {types.PossibleLikelihood, types.HighImpact},
	"missing-identity-store":                 {types.Unlikely, types.LowImpact},
	"missing-network-segmentation":           {types.PossibleLikelihood, types.MediumImpact},
	"missing-vault":                          {types.Unlikely, types.MediumImpact},
	"missing-vault-isolation":                {types.Unlikely, types.HighImpact},
	"missing-waf":                            {types.PossibleLikelihood, types.MediumImpact},
	"mixed-targets-on-shared-runtime":        {types.Unlikely, types.MediumImpact},
	"path-traversal":                         {types.Likely, types.HighImpact},
	"push-instead-of-pull-deployment":        {types.Unlikely, types.MediumImpact},
	"search-query-injection":                 {types.PossibleLikelihood, types.HighImpact},
	"server-side-request-forgery":            {types.PossibleLikelihood, types.MediumImpact},
	"service-registry-poisoning":             {types.Unlikely, types.HighImpact},
	"sql-nosql-injection":                    {types.Likely, types.VeryHighImpact},
	"unchecked-deployment":                   {types.Likely, types.MediumImpact},
	"unencrypted-asset":                      {types.Unlikely, types.MediumImpact},
	"unencrypted-communication":              {types.PossibleLikelihood, types.HighImpact},
	"unguarded-access-from-internet":         {types.Likely, types.MediumImpact},
	"unguarded-direct-datastore-access":      {types.PossibleLikelihood, types.MediumImpact},
	"untrusted-deserialization":              {types.PossibleLikelihood, types.VeryHighImpact},
	"xml-external-entity":                    {types.PossibleLikelihood, types.HighImpact},
}

// Ratings the kitchen sink's own shape explains:
//   - it models no trust boundaries, so every asset shares one execution environment and the
//     isolation rules take their one-level same-execution-environment step;
//   - it models no DevOps links, so unchecked-deployment has no deployment target to rate
//     (rank 0, one level below its Low baseline, clamped).
var builtinBranchOnKitchenSink = map[string]calibratedRating{
	"unchecked-deployment":                {types.Likely, types.LowImpact},
	"missing-identity-provider-isolation": {types.Likely, types.HighImpact},
	"missing-vault-isolation":             {types.PossibleLikelihood, types.HighImpact},
}

func builtinProfileTModel(t *testing.T) *types.Model {
	t.Helper()
	model := profileTModel(t)
	model.IncomingTechnicalCommunicationLinksMappedByTargetId = map[string][]*types.CommunicationLink{}
	for _, asset := range model.TechnicalAssets {
		asset.Internet = false
		for _, link := range asset.CommunicationLinks {
			link.DataAssetsSent = []string{"data"}
			model.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId] = append(
				model.IncomingTechnicalCommunicationLinksMappedByTargetId[link.TargetId], link)
		}
	}
	return model
}

func TestBuiltinRulesMatchTheirCalibratedRatingOnProfileT(t *testing.T) {
	rules := risks.GetBuiltInRiskRules()
	model := builtinProfileTModel(t)
	ids := make([]string, 0, len(builtinCalibratedOnProfileT))
	for id := range builtinCalibratedOnProfileT {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fired := []string{}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			rule, ok := rules[id]
			if !assert.True(t, ok, "no built-in rule %q", id) {
				return
			}
			generated, err := rule.GenerateRisks(model)
			assert.NoError(t, err)
			if len(generated) > 0 {
				fired = append(fired, id)
			}
			want := builtinCalibratedOnProfileT[id]
			if branch, ok := builtinBranchOnKitchenSink[id]; ok {
				want = branch
			}
			for _, risk := range generated {
				assert.Equal(t, want.likelihood.String(), risk.ExploitationLikelihood.String(), "likelihood at %s", risk.MostRelevantTechnicalAssetId)
				assert.Equal(t, want.impact.String(), risk.ExploitationImpact.String(), "impact at %s", risk.MostRelevantTechnicalAssetId)
			}
		})
	}
	// The built-ins whose rating this check actually verifies. If the set changes, the check now
	// covers more or fewer rules: update the list deliberately.
	assert.Equal(t, []string{
		"accidental-secret-leak", "cluster-control-plane-audit-gap", "container-platform-escape",
		"cross-site-scripting", "missing-authentication", "missing-identity-provider-isolation",
		"missing-vault-isolation", "server-side-request-forgery", "service-registry-poisoning",
		"unchecked-deployment", "unencrypted-asset", "unencrypted-communication",
		"untrusted-deserialization",
	}, fired)
}
