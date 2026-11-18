package scripts

// Dimension check: profile T rates confidentiality and integrity at the same rank, so it cannot
// tell a rule that steps on the wrong dimension, or reads the wrong rating source, from a correct
// one. Here every built-in and script rule runs on the kitchen-sink model with only one dimension
// high at a time (assets, data and link data alike), and each finding's impact must be the
// approved baseline plus the symmetric step on the rule's approved dimension.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

type cia int

const (
	dimC cia = iota
	dimI
	dimA
	dimCI   // higher of confidentiality and integrity (injection, code execution, cleartext links)
	dimCIA  // highest of the three (elevation of privilege)
	dimNone // fixed baseline, no CIA step (whole-model checks)
)

type approvedImpact struct {
	baseline  types.RiskExploitationImpact
	dimension cia
}

// approvedImpactByRule is generated from the approved calibration table, with the decisions of
// the 2026-11-18 review applied (see docs/risk-methodology.md, "Risk calibration").
var approvedImpactByRule = map[string]approvedImpact{
	"code-backdooring":                              {types.MediumImpact, dimCI},
	"container-baseimage-backdooring":               {types.HighImpact, dimI},
	"container-platform-escape":                     {types.HighImpact, dimCIA},
	"cross-site-request-forgery":                    {types.LowImpact, dimI},
	"cross-site-scripting":                          {types.MediumImpact, dimCI},
	"dos-risky-access-across-trust-boundary":        {types.LowImpact, dimA},
	"ldap-injection":                                {types.MediumImpact, dimCI},
	"missing-authentication":                        {types.MediumImpact, dimCIA},
	"missing-authentication-second-factor":          {types.MediumImpact, dimCIA},
	"missing-build-infrastructure":                  {types.LowImpact, dimNone},
	"missing-cloud-hardening":                       {types.LowImpact, dimI},
	"missing-file-validation":                       {types.MediumImpact, dimI},
	"missing-hardening":                             {types.LowImpact, dimI},
	"missing-identity-propagation":                  {types.LowImpact, dimCIA},
	"missing-identity-provider-isolation":           {types.MediumImpact, dimCIA},
	"missing-identity-store":                        {types.LowImpact, dimNone},
	"missing-network-segmentation":                  {types.LowImpact, dimCIA},
	"missing-vault":                                 {types.LowImpact, dimC},
	"missing-vault-isolation":                       {types.MediumImpact, dimCIA},
	"missing-waf":                                   {types.LowImpact, dimI},
	"mixed-targets-on-shared-runtime":               {types.LowImpact, dimCIA},
	"path-traversal":                                {types.MediumImpact, dimC},
	"push-instead-of-pull-deployment":               {types.LowImpact, dimI},
	"search-query-injection":                        {types.MediumImpact, dimCI},
	"server-side-request-forgery":                   {types.LowImpact, dimC},
	"service-registry-poisoning":                    {types.MediumImpact, dimI},
	"sql-nosql-injection":                           {types.HighImpact, dimCI},
	"unchecked-deployment":                          {types.LowImpact, dimI},
	"unencrypted-asset":                             {types.LowImpact, dimC},
	"unencrypted-communication":                     {types.MediumImpact, dimCI},
	"unguarded-access-from-internet":                {types.LowImpact, dimCIA},
	"unguarded-direct-datastore-access":             {types.LowImpact, dimCIA},
	"untrusted-deserialization":                     {types.HighImpact, dimCI},
	"xml-external-entity":                           {types.MediumImpact, dimC},
	"accidental-secret-leak":                        {types.LowImpact, dimC},
	"ai-adversarial-evasion":                        {types.MediumImpact, dimI},
	"ai-agent-identity-privilege-abuse":             {types.MediumImpact, dimCIA},
	"ai-cascading-agent-failures":                   {types.MediumImpact, dimA},
	"ai-content-provenance-tampering":               {types.MediumImpact, dimI},
	"ai-cross-context-bleed":                        {types.MediumImpact, dimC},
	"ai-excessive-agency-tool-misuse":               {types.MediumImpact, dimCIA},
	"ai-hidden-context-exposure":                    {types.LowImpact, dimC},
	"ai-improper-output-handling":                   {types.MediumImpact, dimI},
	"ai-inference-data-reconstruction":              {types.LowImpact, dimC},
	"ai-insecure-inter-agent-communication":         {types.MediumImpact, dimI},
	"ai-model-exfiltration":                         {types.MediumImpact, dimC},
	"ai-operational-control-gap":                    {types.LowImpact, dimI},
	"ai-rag-corpus-poisoning":                       {types.MediumImpact, dimI},
	"ai-retrieval-resilience-gap":                   {types.LowImpact, dimA},
	"ai-security-tooling-compromise":                {types.HighImpact, dimCIA},
	"ai-sensitive-information-disclosure":           {types.MediumImpact, dimC},
	"ai-supply-chain-compromise":                    {types.HighImpact, dimI},
	"ai-synthetic-data-leakage":                     {types.LowImpact, dimC},
	"ai-telemetry-prompt-log-leakage":               {types.MediumImpact, dimC},
	"ai-training-data-model-poisoning":              {types.MediumImpact, dimI},
	"ai-unbounded-consumption":                      {types.MediumImpact, dimA},
	"ai-unsafe-nl-data-gateway":                     {types.MediumImpact, dimC},
	"ai-vector-store-exposure":                      {types.MediumImpact, dimC},
	"air-ground-station-c2-link-hijack":             {types.MediumImpact, dimI},
	"air-vehicle-gps-spoofing":                      {types.MediumImpact, dimI},
	"baseline-security-event-logging-gap":           {types.LowImpact, dimI},
	"broken-function-level-authorization":           {types.HighImpact, dimCIA},
	"broken-object-level-authorization":             {types.MediumImpact, dimC},
	"broken-object-property-level-authorization":    {types.MediumImpact, dimI},
	"cds-data-diode-unidirectionality-gap":          {types.HighImpact, dimI},
	"cds-guard-ruleset-bypass":                      {types.MediumImpact, dimI},
	"certificate-validation-soft-fail":              {types.MediumImpact, dimI},
	"cicd-pipeline-tampering-outside-repo":          {types.MediumImpact, dimI},
	"cluster-control-plane-audit-gap":               {types.LowImpact, dimI},
	"cui-telemetry-spillage":                        {types.LowImpact, dimC},
	"dangerous-container-capabilities":              {types.MediumImpact, dimCIA},
	"data-store-audit-detection-gap":                {types.LowImpact, dimI},
	"dependency-confusion-internal-namespace":       {types.HighImpact, dimI},
	"endpoint-security-manager-fleet-compromise":    {types.HighImpact, dimCIA},
	"hardcoded-credentials-secrets-sprawl":          {types.MediumImpact, dimC},
	"ics-controller-unauthenticated-protocol":       {types.HighImpact, dimI},
	"insecure-session-management":                   {types.MediumImpact, dimI},
	"insufficient-audit-logging":                    {types.LowImpact, dimI},
	"key-management-separation-of-duties-violation": {types.LowImpact, dimCIA},
	"key-rotation-escrow-neglect":                   {types.LowImpact, dimC},
	"key-storage-ownership-hardening-gap":           {types.LowImpact, dimC},
	"malicious-install-script-execution":            {types.HighImpact, dimI},
	"media-sanitization-procedure-gap":              {types.LowImpact, dimC},
	"mishandling-exceptional-conditions":            {types.LowImpact, dimCIA},
	"missing-data-retention-schedule":               {types.LowImpact, dimC},
	"missing-endpoint-security-agents":              {types.LowImpact, dimC},
	"missing-network-micro-segmentation":            {types.LowImpact, dimCIA},
	"multi-tenant-data-isolation":                   {types.HighImpact, dimC},
	"mutable-container-filesystem":                  {types.LowImpact, dimI},
	"network-encryptor-common-mode-failure":         {types.HighImpact, dimC},
	"os-command-injection":                          {types.HighImpact, dimCIA},
	"security-control-tamper-resistance-gap":        {types.LowImpact, dimC},
	"space-ground-station-rogue-uplink":             {types.HighImpact, dimI},
	"space-vehicle-bus-segmentation-gap":            {types.HighImpact, dimI},
	"unencrypted-virtual-disk":                      {types.LowImpact, dimC},
	"unhardened-os-missing-patch-management":        {types.MediumImpact, dimCIA},
	"unscanned-data-store":                          {types.LowImpact, dimC},
	"untrusted-container-image":                     {types.MediumImpact, dimI},
	"vulnerability-scanner-credential-exposure":     {types.HighImpact, dimCIA},
	"vulnerable-outdated-dependency":                {types.MediumImpact, dimI},
}

// Impacts the kitchen sink's own shape decides, not the rule's dimension:
//   - unencrypted-communication: the kitchen sink's unencrypted links carry authentication data,
//     which counts as confidential whatever the profile, so the step is always +1;
//   - unchecked-deployment: no DevOps links, so no deployment target to rate (rank 0).
var dimensionCheckFixedRank = map[string]int{
	"unencrypted-communication": int(types.Confidential),
	"unchecked-deployment":      0,
}

type dimensionProfile struct {
	name                    string
	confidentiality         types.Confidentiality
	integrity, availability types.Criticality
}

var dimensionProfiles = []dimensionProfile{
	{"confidentiality only", types.Confidential, types.Operational, types.Operational},
	{"integrity only", types.Internal, types.Critical, types.Operational},
	{"availability only", types.Internal, types.Operational, types.Critical},
}

func (p dimensionProfile) rank(dimension cia) int {
	c, i, a := int(p.confidentiality), int(p.integrity), int(p.availability)
	switch dimension {
	case dimC:
		return c
	case dimI:
		return i
	case dimA:
		return a
	case dimCI:
		return max(c, i)
	default:
		return max(c, i, a)
	}
}

func dimensionModel(t *testing.T, p dimensionProfile) *types.Model {
	t.Helper()
	model := builtinProfileTModel(t)
	for _, data := range model.DataAssets {
		data.Confidentiality, data.Integrity, data.Availability = p.confidentiality, p.integrity, p.availability
	}
	for _, asset := range model.TechnicalAssets {
		asset.Confidentiality, asset.Integrity, asset.Availability = p.confidentiality, p.integrity, p.availability
	}
	return model
}

func TestEveryRuleStepsImpactOnItsApprovedDimension(t *testing.T) {
	rules := map[string]types.RiskRule{}
	for id, rule := range risks.GetBuiltInRiskRules() {
		rules[id] = rule
	}
	for id, rule := range loadAllScriptRules(t) {
		rules[id] = rule // a script rule shadows the built-in of the same id, as at runtime
	}
	ids := make([]string, 0, len(approvedImpactByRule))
	for id := range approvedImpactByRule {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	checked := map[string]bool{}
	for _, profile := range dimensionProfiles {
		model := dimensionModel(t, profile)
		for _, id := range ids {
			rule, ok := rules[id]
			if !assert.True(t, ok, "no rule %q", id) {
				continue
			}
			generated, err := rule.GenerateRisks(model)
			assert.NoError(t, err, "%s on %s", id, profile.name)
			approved := approvedImpactByRule[id]
			want := approved.baseline
			if approved.dimension != dimNone {
				rank := profile.rank(approved.dimension)
				if fixed, ok := dimensionCheckFixedRank[id]; ok {
					rank = fixed
				}
				want = types.AdjustImpactForRank(approved.baseline, rank)
			}
			for _, risk := range generated {
				checked[id] = true
				assert.Equal(t, want.String(), risk.ExploitationImpact.String(), "%s on %s at %s",
					id, profile.name, risk.MostRelevantTechnicalAssetId)
			}
		}
	}
	// Rules the kitchen sink can't fire in any single-dimension profile; their unit tests cover them.
	assert.GreaterOrEqual(t, len(checked), 60, "rules exercised by the dimension check")
	t.Logf("dimension check exercised %d of %d rules", len(checked), len(ids))
}
