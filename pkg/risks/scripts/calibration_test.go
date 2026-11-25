package scripts

// Calibration check: every script rule, run on the typical IL5 reference profile ("T":
// confidential / critical / important, RAA 30, no rule-specific steps), must produce the final
// rating approved in threat-modeling-2's docs/risk-methodology.md ("Risk calibration" and its
// appendix). A change to a rule's baseline or step logic that moves its rating on T fails here,
// so it has to be a deliberate change to both the rule and this table.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

type calibratedRating struct {
	likelihood types.RiskExploitationLikelihood
	impact     types.RiskExploitationImpact
}

// calibratedOnProfileT is generated from the approved calibration table.
var calibratedOnProfileT = map[string]calibratedRating{
	"ai-adversarial-evasion":                        {types.PossibleLikelihood, types.HighImpact},
	"ai-agent-identity-privilege-abuse":             {types.Likely, types.HighImpact},
	"ai-cascading-agent-failures":                   {types.PossibleLikelihood, types.MediumImpact},
	"ai-content-provenance-tampering":               {types.Likely, types.HighImpact},
	"ai-cross-context-bleed":                        {types.PossibleLikelihood, types.HighImpact},
	"ai-excessive-agency-tool-misuse":               {types.Likely, types.HighImpact},
	"ai-hidden-context-exposure":                    {types.VeryLikely, types.MediumImpact},
	"ai-improper-output-handling":                   {types.Likely, types.HighImpact},
	"ai-inference-data-reconstruction":              {types.VeryLikely, types.MediumImpact},
	"ai-insecure-inter-agent-communication":         {types.PossibleLikelihood, types.HighImpact},
	"ai-model-exfiltration":                         {types.Likely, types.HighImpact},
	"ai-operational-control-gap":                    {types.PossibleLikelihood, types.MediumImpact},
	"ai-rag-corpus-poisoning":                       {types.Likely, types.HighImpact},
	"ai-retrieval-resilience-gap":                   {types.Unlikely, types.MediumImpact},
	"ai-security-tooling-compromise":                {types.Unlikely, types.VeryHighImpact},
	"ai-sensitive-information-disclosure":           {types.Likely, types.HighImpact},
	"ai-supply-chain-compromise":                    {types.PossibleLikelihood, types.VeryHighImpact},
	"ai-synthetic-data-leakage":                     {types.PossibleLikelihood, types.MediumImpact},
	"ai-telemetry-prompt-log-leakage":               {types.Likely, types.HighImpact},
	"ai-training-data-model-poisoning":              {types.Unlikely, types.HighImpact},
	"ai-unbounded-consumption":                      {types.Likely, types.MediumImpact},
	"ai-unsafe-nl-data-gateway":                     {types.PossibleLikelihood, types.HighImpact},
	"ai-vector-store-exposure":                      {types.Unlikely, types.HighImpact},
	"air-ground-station-c2-link-hijack":             {types.PossibleLikelihood, types.HighImpact},
	"air-vehicle-gps-spoofing":                      {types.Likely, types.HighImpact},
	"broken-function-level-authorization":           {types.Likely, types.VeryHighImpact},
	"broken-object-level-authorization":             {types.Likely, types.HighImpact},
	"broken-object-property-level-authorization":    {types.PossibleLikelihood, types.HighImpact},
	"cds-data-diode-unidirectionality-gap":          {types.Unlikely, types.VeryHighImpact},
	"cds-guard-ruleset-bypass":                      {types.PossibleLikelihood, types.HighImpact},
	"certificate-validation-soft-fail":              {types.PossibleLikelihood, types.HighImpact},
	"cicd-pipeline-tampering-outside-repo":          {types.Unlikely, types.HighImpact},
	"cui-telemetry-spillage":                        {types.Likely, types.MediumImpact},
	"dangerous-container-capabilities":              {types.PossibleLikelihood, types.HighImpact},
	"data-store-audit-detection-gap":                {types.Likely, types.MediumImpact},
	"dependency-confusion-internal-namespace":       {types.Likely, types.VeryHighImpact},
	"endpoint-security-manager-fleet-compromise":    {types.Unlikely, types.VeryHighImpact},
	"hardcoded-credentials-secrets-sprawl":          {types.Likely, types.HighImpact},
	"ics-controller-unauthenticated-protocol":       {types.Likely, types.VeryHighImpact},
	"insecure-session-management":                   {types.Likely, types.HighImpact},
	"insufficient-audit-logging":                    {types.PossibleLikelihood, types.MediumImpact},
	"key-management-separation-of-duties-violation": {types.Unlikely, types.MediumImpact},
	"key-rotation-escrow-neglect":                   {types.Unlikely, types.MediumImpact},
	"key-storage-ownership-hardening-gap":           {types.Unlikely, types.MediumImpact},
	"malicious-install-script-execution":            {types.Likely, types.VeryHighImpact},
	"media-sanitization-procedure-gap":              {types.PossibleLikelihood, types.MediumImpact},
	"mishandling-exceptional-conditions":            {types.PossibleLikelihood, types.MediumImpact},
	"missing-data-retention-schedule":               {types.PossibleLikelihood, types.MediumImpact},
	"missing-endpoint-security-agents":              {types.Likely, types.MediumImpact},
	"missing-network-micro-segmentation":            {types.PossibleLikelihood, types.MediumImpact},
	"multi-tenant-data-isolation":                   {types.PossibleLikelihood, types.VeryHighImpact},
	"mutable-container-filesystem":                  {types.PossibleLikelihood, types.MediumImpact},
	"network-encryptor-common-mode-failure":         {types.Unlikely, types.VeryHighImpact},
	"os-command-injection":                          {types.Likely, types.VeryHighImpact},
	"security-control-tamper-resistance-gap":        {types.Unlikely, types.MediumImpact},
	"space-ground-station-rogue-uplink":             {types.Unlikely, types.VeryHighImpact},
	"space-vehicle-bus-segmentation-gap":            {types.Unlikely, types.VeryHighImpact},
	"unhardened-os-missing-patch-management":        {types.Likely, types.HighImpact},
	"unscanned-data-store":                          {types.PossibleLikelihood, types.MediumImpact},
	"untrusted-container-image":                     {types.Likely, types.HighImpact},
	"vulnerability-scanner-credential-exposure":     {types.PossibleLikelihood, types.VeryHighImpact},
	"vulnerable-outdated-dependency":                {types.Likely, types.HighImpact},
}

// Rules that cannot fire on profile T itself run on a variant that meets their precondition.
// The calibrated rating is the one the rule produces where it fires.
var calibrationProfileVariants = map[string]func(*types.Model){
	// Fires only on retrieval rated critical or mission-critical for availability.
	"ai-retrieval-resilience-gap": func(model *types.Model) {
		for _, asset := range model.TechnicalAssets {
			asset.Availability = types.Critical
		}
	},
}

func profileTModel(t *testing.T) *types.Model {
	t.Helper()
	model := kitchenSinkModel(t)
	for _, data := range model.DataAssets {
		data.Confidentiality, data.Integrity, data.Availability = types.Confidential, types.Critical, types.Important
	}
	for _, asset := range model.TechnicalAssets {
		asset.Confidentiality, asset.Integrity, asset.Availability = types.Confidential, types.Critical, types.Important
		asset.RAA = 30
	}
	return model
}

func TestEveryScriptRuleMatchesItsCalibratedRatingOnProfileT(t *testing.T) {
	rules := loadAllScriptRules(t)
	assert.Len(t, calibratedOnProfileT, len(rules), "every script rule needs a calibrated rating, and no stale entries")

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			expected, ok := calibratedOnProfileT[id]
			if !assert.True(t, ok, "no calibrated rating for %q", id) {
				return
			}
			model := profileTModel(t)
			if variant, ok := calibrationProfileVariants[id]; ok {
				variant(model)
			}
			generated, err := rules[id].GenerateRisks(model)
			assert.NoError(t, err)
			assert.NotEmpty(t, generated, "rule must fire on profile T (or its variant) for the check to mean anything")
			for _, risk := range generated {
				want := expected
				// Profile T is not internet-exposed, but the kitchen sink's LLM endpoint is, so that
				// exposure-gated rules fire. A finding there takes the internet step on top.
				if asset := model.TechnicalAssets[risk.MostRelevantTechnicalAssetId]; asset != nil && asset.IsInternetExposed() {
					want.likelihood = types.ClampLikelihood(int(want.likelihood) + 1)
				}
				assert.Equal(t, want.likelihood.String(), risk.ExploitationLikelihood.String(), "likelihood at %s", risk.MostRelevantTechnicalAssetId)
				assert.Equal(t, want.impact.String(), risk.ExploitationImpact.String(), "impact at %s", risk.MostRelevantTechnicalAssetId)
				assert.Equal(t, types.CalculateSeverity(want.likelihood, want.impact), risk.Severity, "severity at %s", risk.MostRelevantTechnicalAssetId)
			}
		})
	}
}
