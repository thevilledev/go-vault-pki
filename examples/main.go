package main

import (
	"net/http"

	"github.com/go-chi/chi"
	vapi "github.com/hashicorp/vault/api"
	vaultpki "github.com/vtorhonen/go-http-vault-pki"
)

const (
	pkiMount  = "pki"
	pkiRole   = "service-consul"
	serviceCN = "foo.service.consul"
	certTTL   = "3600"
)

func main() {
	cfg := vapi.DefaultConfig()
	cfg.ConfigureTLS(&vapi.TLSConfig{
		Insecure: true,
	})
	v, err := vaultpki.NewWithConfig(pkiMount, pkiRole, serviceCN, certTTL, cfg)
	if err != nil {
		panic(err)
	}
	tlsCfg, err := v.RefreshTLSConfig()
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})
	srv := http.Server{
		Addr:      "127.0.0.1:18080",
		Handler:   r,
		TLSConfig: tlsCfg,
	}
	err = srv.ListenAndServeTLS("", "")
	if err != nil {
		panic(err)
	}
}
