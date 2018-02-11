# go-http-vault-pki

This Go library works as a gateway for any Go service that wants to use Vault PKI for issuing
certificates. This is especially useful for services that would like to use HTTP/2 in full with
end-to-end encryption and by utilizing a pre-existing PKI.

Library exposes the following two methods:

- `RefreshTLSConfig()`: issues a new TLS certificate and returns a
[tls.Config instance from net/http](https://golang.org/pkg/crypto/tls/#Config) with the
certificate chain. This can then be used in any HTTP router, like
[go-chi](https://github.com/go-chi/chi).
- `IssueNewCertificate()`: issues a new TLS certificate and returns
an [api.Secret instance](https://godoc.org/github.com/hashicorp/vault/api#Secret) described
by the Vault API. Certificate data can be accessed through `api.Secret.Data` map.

# Prequisites for using the library

Make sure you have a Vault PKI properly configured. If not,
[read the documentation](https://www.vaultproject.io/docs/secrets/pki/index.html). You must
set up a root CA or an intermediate CA (signed by another CA) in your Vault. You'll then have to
set up a Vault PKI role, which can issue certificates under that CA with specific
Common Names (CN). You'll need to configure a Vault policy, so tokens with specific Vault
policies can issue new certificates. In any case you probably end up in a situation where
you have a service called `foo` which would like to issue a certificate for
`foo.datacenter.whatever` or `foo.company.tld` or whatever.

# Using the library

Make sure you expose the following environment variables for your service:

- `VAULT_TOKEN`: A Vault token, which has necessary rights to a PKI role for issuing
certificates.
- `VAULT_ADDR`: Vault address, for example `https//vault.service.consul:8200`

A job scheduler such as Nomad or Kubernetes does this for you automatically.

Then, while setting up HTTP router in your service you should call `RefreshTLSConfig()`.
For example like this (but with proper error handling):

```golang
// Set up VaultPKI instance and get a new TLSConfig
v, err := vaultpki.NewWithConfig(pkiMount, pkiRole, serviceCN, certTTL)
tlsCfg, err := v.RefreshTLSConfig()

// Set up our HTTP router
r := chi.NewRouter()
r.Get("/", func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("welcome"))
})

// Set up HTTP server
srv := http.Server{
    Addr:      "127.0.0.1:18080",
	Handler:   r,
	TLSConfig: tlsCfg,
}
err = srv.ListenAndServeTLS("", "")
```

For a complete example see [examples/main.go](examples/main.go) or [main_test.go](main_test.go).
