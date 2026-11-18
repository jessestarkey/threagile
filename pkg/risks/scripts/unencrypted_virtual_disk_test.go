package scripts

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threagile/threagile/pkg/types"
)

//go:embed unencrypted-virtual-disk.yaml
var unencryptedVirtualDisk string

// Encryption "none" is the zero value, so the script engine sees it as a missing field; the rule
// must treat missing the same as an explicit none, and stay quiet on an encrypted disk.
func TestUnencryptedVirtualDiskFiresOnlyWithoutEncryption(t *testing.T) {
	vm := func(id string, machine types.TechnicalAssetMachine, encryption types.EncryptionStyle) *types.TechnicalAsset {
		asset := agencyAsset(id, "web-application")
		asset.Machine = machine
		asset.Encryption = encryption
		return asset
	}
	model := secretsSprawlModel(
		vm("plain", types.Virtual, types.NoneEncryption),
		vm("encrypted", types.Virtual, types.Transparent),
		vm("server", types.Physical, types.NoneEncryption),
	)

	fired := firedOn(generateScriptRisks(t, unencryptedVirtualDisk, model))

	assert.Contains(t, fired, "plain")
	assert.NotContains(t, fired, "encrypted")
	assert.NotContains(t, fired, "server")
}
