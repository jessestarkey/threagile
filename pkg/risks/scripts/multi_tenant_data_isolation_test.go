package scripts

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed multi-tenant-data-isolation.yaml
var multiTenantDataIsolation string

// Tenant isolation in queries, caching, and jobs is code the application team writes, so a
// provider-shared managed service marked multi_tenant does not fire.
func TestMultiTenantIsolationNeedsTheAssetsOwnCode(t *testing.T) {
	custom := agencyAsset("app", "web-application")
	custom.MultiTenant, custom.CustomDevelopedParts = true, true
	managed := agencyAsset("waf", "waf")
	managed.MultiTenant, managed.CustomDevelopedParts = true, false
	single := agencyAsset("single", "web-application")
	single.CustomDevelopedParts = true

	fired := firedOn(generateScriptRisks(t, multiTenantDataIsolation, boundaryModel(map[string]string{}, custom, managed, single)))

	assert.ElementsMatch(t, []string{"app"}, keys(fired))
}
