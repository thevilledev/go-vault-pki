package vaultpki // "import github.com/vtorhonen/go-vault-pki"

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api"
)

var (
	ErrCertIssueFailed = errors.New("failed to issue new certificate from vault")
)

// VaultPKI represents a Vault PKI role for issuing certificates
type VaultPKI struct {
	path    string
	role    string
	cn      string
	certTTL string
	Client  *api.Client
}

// New returns a new VaultPKI instance by using default
// Vault API configuration
func New(path, role, cn, certTTL string) (*VaultPKI, error) {
	cfg := api.DefaultConfig()
	return NewWithConfig(path, role, cn, certTTL, cfg)
}

// NewWithConfig returns a new VaultPKI instance by allowing
// Vault API config customization through 'cfg' parameter
func NewWithConfig(path, role, cn, certTTL string, cfg *api.Config) (*VaultPKI, error) {
	v, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	p := fmt.Sprintf("%s/issue/%s", path, role)
	return &VaultPKI{
		path:    p,
		cn:      cn,
		certTTL: certTTL,
		Client:  v,
	}, nil
}

// IssueNewCertificate issues a new certificate through Vault API
// call and returns the API secret response as is.
func (v *VaultPKI) IssueNewCertificate() (*api.Secret, error) {
	data := map[string]interface{}{
		"common_name": v.cn,
		"ttl":         v.certTTL,
	}
	r, err := v.Client.Logical().Write(v.path, data)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrCertIssueFailed
	}
	return r, nil
}

// RefreshTLSConfig issues a new certificate and returns
// a corresponding net/http tls.Config instance which
// can be used in various HTTP routers
func (v *VaultPKI) RefreshTLSConfig() (*tls.Config, error) {
	d, err := v.IssueNewCertificate()
	if err != nil {
		return nil, err
	}
	caPEM := d.Data["issuing_ca"].(string)
	crtPEM := d.Data["certificate"].(string)
	// Create certificate chain
	chainPEM := []byte(crtPEM + "\n" + caPEM)
	keyPEM := []byte(d.Data["private_key"].(string))
	crt, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Only one certificate chain is supported at the moment
	crtSlice := make([]tls.Certificate, 1)
	crtSlice[0] = crt
	tlsCfg := &tls.Config{
		Certificates: crtSlice,
	}
	return tlsCfg, nil
}
