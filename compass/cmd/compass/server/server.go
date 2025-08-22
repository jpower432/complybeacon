package server

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/complytime/complybeacon/compass/api"
	compass "github.com/complytime/complybeacon/compass/service"
)

func NewServer(service *compass.Service, port string) *http.Server {
	swagger, err := api.GetSwagger()
	if err != nil {
		log.Fatalf("Error loading swagger spec\n: %s", err)
	}

	// Clear out the servers array in the swagger spec, that skips validating
	// that server names match. We don't know how this thing will be run.
	swagger.Servers = nil

	// This is how you set up a basic chi router
	r := chi.NewRouter()

	// Use middleware to check all requests against the
	// OpenAPI schema.
	// FIXME(jpower432): Investigate request schema validation middleware.
	// Currently throwing a 400 with client generated code.
	//r.Use(middleware.OapiRequestValidator(swagger))

	// We now register our petStore above as the handler for the interface
	api.HandlerFromMux(service, r)

	s := &http.Server{
		Handler:           r,
		Addr:              net.JoinHostPort("0.0.0.0", port),
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

func SetupTLS(server *http.Server, config Config) (string, string) {
	// TODO: Allow loosening here through configuration
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	server.TLSConfig = tlsConfig

	if config.Certificate.PublicKey == "" {
		log.Fatal("Invalid certification configuration. Please add certConfig.cert to the configuration.")
	}

	if config.Certificate.PrivateKey == "" {
		log.Fatal("Invalid certification configuration. Please add certConfig.key to the configuration.")
	}

	return config.Certificate.PublicKey, config.Certificate.PrivateKey
}
