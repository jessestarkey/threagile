package scripts

// Every built-in and script rule must carry the finding class approved in threat-modeling-2's
// docs/risk-methodology.md ("Risk calibration"): weakness-shown when the model's own facts show
// the weakness, control-not-evidenced when the rule fires because an interface exists.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/types"
)

// approvedFindingClass is generated from the approved calibration table. accidental-secret-leak
// has a built-in and a script rule of the same id; the script one shadows the built-in, and both
// are control-not-evidenced.
var approvedFindingClass = map[string]string{
	"accidental-secret-leak":                        types.FindingClassControlNotEvidenced,
	"ai-adversarial-evasion":                        types.FindingClassControlNotEvidenced,
	"ai-agent-identity-privilege-abuse":             types.FindingClassWeaknessShown,
	"ai-cascading-agent-failures":                   types.FindingClassWeaknessShown,
	"ai-content-provenance-tampering":               types.FindingClassControlNotEvidenced,
	"ai-cross-context-bleed":                        types.FindingClassWeaknessShown,
	"ai-excessive-agency-tool-misuse":               types.FindingClassWeaknessShown,
	"ai-hidden-context-exposure":                    types.FindingClassWeaknessShown,
	"ai-improper-output-handling":                   types.FindingClassWeaknessShown,
	"ai-inference-data-reconstruction":              types.FindingClassWeaknessShown,
	"ai-insecure-inter-agent-communication":         types.FindingClassWeaknessShown,
	"ai-model-exfiltration":                         types.FindingClassControlNotEvidenced,
	"ai-operational-control-gap":                    types.FindingClassControlNotEvidenced,
	"ai-rag-corpus-poisoning":                       types.FindingClassWeaknessShown,
	"ai-retrieval-resilience-gap":                   types.FindingClassControlNotEvidenced,
	"ai-security-tooling-compromise":                types.FindingClassControlNotEvidenced,
	"ai-sensitive-information-disclosure":           types.FindingClassWeaknessShown,
	"ai-supply-chain-compromise":                    types.FindingClassControlNotEvidenced,
	"ai-synthetic-data-leakage":                     types.FindingClassWeaknessShown,
	"ai-telemetry-prompt-log-leakage":               types.FindingClassControlNotEvidenced,
	"ai-training-data-model-poisoning":              types.FindingClassControlNotEvidenced,
	"ai-unbounded-consumption":                      types.FindingClassWeaknessShown,
	"ai-unsafe-nl-data-gateway":                     types.FindingClassWeaknessShown,
	"ai-vector-store-exposure":                      types.FindingClassControlNotEvidenced,
	"air-ground-station-c2-link-hijack":             types.FindingClassControlNotEvidenced,
	"air-vehicle-gps-spoofing":                      types.FindingClassControlNotEvidenced,
	"baseline-security-event-logging-gap":           types.FindingClassControlNotEvidenced,
	"broken-function-level-authorization":           types.FindingClassControlNotEvidenced,
	"broken-object-level-authorization":             types.FindingClassControlNotEvidenced,
	"broken-object-property-level-authorization":    types.FindingClassControlNotEvidenced,
	"cds-data-diode-unidirectionality-gap":          types.FindingClassControlNotEvidenced,
	"cds-guard-ruleset-bypass":                      types.FindingClassControlNotEvidenced,
	"certificate-validation-soft-fail":              types.FindingClassControlNotEvidenced,
	"cicd-pipeline-tampering-outside-repo":          types.FindingClassControlNotEvidenced,
	"cluster-control-plane-audit-gap":               types.FindingClassControlNotEvidenced,
	"code-backdooring":                              types.FindingClassWeaknessShown,
	"container-baseimage-backdooring":               types.FindingClassControlNotEvidenced,
	"container-platform-escape":                     types.FindingClassControlNotEvidenced,
	"cross-site-request-forgery":                    types.FindingClassControlNotEvidenced,
	"cross-site-scripting":                          types.FindingClassControlNotEvidenced,
	"cui-telemetry-spillage":                        types.FindingClassControlNotEvidenced,
	"dangerous-container-capabilities":              types.FindingClassControlNotEvidenced,
	"data-store-audit-detection-gap":                types.FindingClassControlNotEvidenced,
	"dependency-confusion-internal-namespace":       types.FindingClassControlNotEvidenced,
	"dos-risky-access-across-trust-boundary":        types.FindingClassWeaknessShown,
	"endpoint-security-manager-fleet-compromise":    types.FindingClassControlNotEvidenced,
	"hardcoded-credentials-secrets-sprawl":          types.FindingClassWeaknessShown,
	"ics-controller-unauthenticated-protocol":       types.FindingClassWeaknessShown,
	"insecure-session-management":                   types.FindingClassControlNotEvidenced,
	"insufficient-audit-logging":                    types.FindingClassControlNotEvidenced,
	"key-management-separation-of-duties-violation": types.FindingClassControlNotEvidenced,
	"key-rotation-escrow-neglect":                   types.FindingClassControlNotEvidenced,
	"key-storage-ownership-hardening-gap":           types.FindingClassControlNotEvidenced,
	"ldap-injection":                                types.FindingClassControlNotEvidenced,
	"malicious-install-script-execution":            types.FindingClassControlNotEvidenced,
	"media-sanitization-procedure-gap":              types.FindingClassControlNotEvidenced,
	"mishandling-exceptional-conditions":            types.FindingClassControlNotEvidenced,
	"missing-authentication":                        types.FindingClassWeaknessShown,
	"missing-authentication-second-factor":          types.FindingClassWeaknessShown,
	"missing-build-infrastructure":                  types.FindingClassControlNotEvidenced,
	"missing-cloud-hardening":                       types.FindingClassControlNotEvidenced,
	"missing-data-retention-schedule":               types.FindingClassControlNotEvidenced,
	"missing-endpoint-security-agents":              types.FindingClassControlNotEvidenced,
	"missing-file-validation":                       types.FindingClassControlNotEvidenced,
	"missing-hardening":                             types.FindingClassControlNotEvidenced,
	"missing-identity-propagation":                  types.FindingClassWeaknessShown,
	"missing-identity-provider-isolation":           types.FindingClassWeaknessShown,
	"missing-identity-store":                        types.FindingClassControlNotEvidenced,
	"missing-network-micro-segmentation":            types.FindingClassControlNotEvidenced,
	"missing-network-segmentation":                  types.FindingClassWeaknessShown,
	"missing-vault":                                 types.FindingClassControlNotEvidenced,
	"missing-vault-isolation":                       types.FindingClassWeaknessShown,
	"missing-waf":                                   types.FindingClassControlNotEvidenced,
	"mixed-targets-on-shared-runtime":               types.FindingClassWeaknessShown,
	"multi-tenant-data-isolation":                   types.FindingClassControlNotEvidenced,
	"mutable-container-filesystem":                  types.FindingClassControlNotEvidenced,
	"network-encryptor-common-mode-failure":         types.FindingClassControlNotEvidenced,
	"os-command-injection":                          types.FindingClassControlNotEvidenced,
	"path-traversal":                                types.FindingClassControlNotEvidenced,
	"push-instead-of-pull-deployment":               types.FindingClassWeaknessShown,
	"search-query-injection":                        types.FindingClassControlNotEvidenced,
	"security-control-tamper-resistance-gap":        types.FindingClassControlNotEvidenced,
	"server-side-request-forgery":                   types.FindingClassControlNotEvidenced,
	"service-registry-poisoning":                    types.FindingClassControlNotEvidenced,
	"space-ground-station-rogue-uplink":             types.FindingClassControlNotEvidenced,
	"space-vehicle-bus-segmentation-gap":            types.FindingClassControlNotEvidenced,
	"sql-nosql-injection":                           types.FindingClassControlNotEvidenced,
	"unchecked-deployment":                          types.FindingClassControlNotEvidenced,
	"unencrypted-asset":                             types.FindingClassWeaknessShown,
	"unencrypted-communication":                     types.FindingClassWeaknessShown,
	"unencrypted-virtual-disk":                      types.FindingClassControlNotEvidenced,
	"unguarded-access-from-internet":                types.FindingClassWeaknessShown,
	"unguarded-direct-datastore-access":             types.FindingClassWeaknessShown,
	"unhardened-os-missing-patch-management":        types.FindingClassControlNotEvidenced,
	"unscanned-data-store":                          types.FindingClassControlNotEvidenced,
	"untrusted-container-image":                     types.FindingClassControlNotEvidenced,
	"untrusted-deserialization":                     types.FindingClassControlNotEvidenced,
	"vulnerability-scanner-credential-exposure":     types.FindingClassControlNotEvidenced,
	"vulnerable-outdated-dependency":                types.FindingClassControlNotEvidenced,
	"xml-external-entity":                           types.FindingClassControlNotEvidenced,
}

func allRuleCategories(t *testing.T) map[string]*types.RiskCategory {
	t.Helper()
	categories := map[string]*types.RiskCategory{}
	for id, rule := range risks.GetBuiltInRiskRules() {
		categories[id] = rule.Category()
	}
	for id, rule := range loadAllScriptRules(t) {
		categories[id] = rule.Category()
	}
	return categories
}

func TestEveryRuleCarriesItsApprovedFindingClass(t *testing.T) {
	categories := allRuleCategories(t)
	ids := make([]string, 0, len(categories))
	for id := range categories {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		category := categories[id]
		want, calibrated := approvedFindingClass[id]
		if category.ModelFailurePossibleReason && !calibrated {
			// model-completeness checks (incomplete model, unnecessary/wrong elements) are not
			// security findings and carry no class
			assert.Empty(t, category.FindingClass, "model-completeness rule %q should not carry a class", id)
			continue
		}
		if !assert.True(t, calibrated, "rule %q has no approved finding class: add it to the calibration table", id) {
			continue
		}
		assert.Equal(t, want, category.FindingClass, "finding class of %q", id)
	}
	for id := range approvedFindingClass {
		assert.Contains(t, categories, id, "stale approved class for %q", id)
	}
}
