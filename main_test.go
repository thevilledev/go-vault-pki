package vaultpki // "import github.com/vtorhonen/go-http-vault-pki"

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/builtin/logical/database"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/builtin/logical/transit"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"

	auditFile "github.com/hashicorp/vault/builtin/audit/file"
	credUserpass "github.com/hashicorp/vault/builtin/credential/userpass"
	vaulthttp "github.com/hashicorp/vault/http"
	logxi "github.com/mgutz/logxi/v1"
)

// Vault mount path for PKI
const pkiPath = "test_pki"

// CN for root CA in 'test_pki'
const rootCN = "my test root ca"

// Vault PKI role for issuing certificates
const roleName = "some-service-role"

// Test domain
const testDomain = "example.tld"

// CN for certificates issued by role
const testCN = "some-service.example.tld"

// Certificate TTL
const certTTL = "3600"

// TestCertIssue creates a test Vault server, issues a new certificate
// and checks that it matches the configured CN in both issuer and certificate.
func TestCertIssue(t *testing.T) {
	// Create test Vault server
	vaultClient, closer := testVaultServer(t)
	defer closer()
	// Create VaultPKI client
	vaultPKI, err := testVaultPKIClient(vaultClient)
	vd, err := vaultPKI.IssueNewCertificate()
	if err != nil {
		t.Fatal(err)
	}
	certPEM := vd.Data["certificate"].(string)
	certDER, _ := pem.Decode([]byte(certPEM))
	if certDER == nil {
		t.Fatal("failed to parse PEM certificate issued by Vault")
	}
	p, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer.CommonName != rootCN {
		t.Fatal("issuer CN does not match what was configured")
	}
	if p.Subject.CommonName != testCN {
		t.Fatal("certificate CN does not match what was configured")
	}
}

// Wrapper for printing out API paths depending
// on configured Vault PKI mountpoint
func pkiAPIPath(path string) string {
	return fmt.Sprintf("%s/%s", pkiPath, path)
}

// testVaultServer creates a test vault cluster and returns a configured API
// client and closer function.
func testVaultServer(t testing.TB) (*api.Client, func()) {
	t.Helper()

	client, _, closer := testVaultServerUnseal(t)

	f, err := client.Logical().Read("/sys/mounts")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("+%v\n", f.Data)
	err = client.Sys().Mount(pkiPath, &api.MountInput{Type: "pki"})
	if err != nil {
		t.Fatal(err)
	}
	f, err = client.Logical().Read("/sys/mounts")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("+%v\n", f.Data)
	rootData := map[string]interface{}{
		"common_name": rootCN,
	}
	r, err := client.Logical().Write(pkiAPIPath("root/generate/internal"), rootData)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("+%v\n", r)
	roleData := map[string]interface{}{
		"allowed_domains":  testDomain,
		"allow_subdomains": true,
	}
	rolePath := pkiAPIPath(fmt.Sprintf("roles/%s", roleName))
	r, err = client.Logical().Write(rolePath, roleData)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("+%v\n", r)
	return client, closer
}

// testVaultPKIClient creates a VaultPKI client by configuring
// Vault address and token in env variables.
func testVaultPKIClient(c *api.Client) (*VaultPKI, error) {
	// Set Vault env variables
	os.Setenv("VAULT_ADDR", c.Address())
	os.Setenv("VAULT_TOKEN", c.Token())
	// Create custom Vault API config to allow insecure
	// connections to our test Vault
	cfg := api.DefaultConfig()
	cfg.ConfigureTLS(&api.TLSConfig{
		Insecure: true,
	})
	s, err := NewWithConfig(pkiPath, roleName, testCN, certTTL, cfg)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Wrapper functions taken from Vault repository. Unfortunately
// these test methods are not exposed.

// testVaultServerUnseal creates a test vault cluster and returns a configured
// API client, list of unseal keys (as strings), and a closer function.
func testVaultServerUnseal(t testing.TB) (*api.Client, []string, func()) {
	t.Helper()

	return testVaultServerCoreConfig(t, &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       logxi.NullLog,
		CredentialBackends: map[string]logical.Factory{
			"userpass": credUserpass.Factory,
		},
		AuditBackends: map[string]audit.Factory{
			"file": auditFile.Factory,
		},
		LogicalBackends: map[string]logical.Factory{
			"database":       database.Factory,
			"generic-leased": vault.LeasedPassthroughBackendFactory,
			"pki":            pki.Factory,
			"transit":        transit.Factory,
		},
	})
}

// testVaultServerCoreConfig creates a new vault cluster with the given core
// configuration. This is a lower-level test helper.
func testVaultServerCoreConfig(t testing.TB, coreConfig *vault.CoreConfig) (*api.Client, []string, func()) {
	t.Helper()

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()

	// Make it easy to get access to the active
	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	// Get the client already setup for us!
	client := cluster.Cores[0].Client
	client.SetToken(cluster.RootToken)

	// Convert the unseal keys to base64 encoded, since these are how the user
	// will get them.
	unsealKeys := make([]string, len(cluster.BarrierKeys))
	for i := range unsealKeys {
		unsealKeys[i] = base64.StdEncoding.EncodeToString(cluster.BarrierKeys[i])
	}

	return client, unsealKeys, func() { defer cluster.Cleanup() }
}
