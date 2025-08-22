package service

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/complytime/complybeacon/compass/api"
	"github.com/complytime/complybeacon/compass/transformer"
	"github.com/complytime/complybeacon/compass/transformer/plugins/basic"
)

var _ api.ServerInterface = (*Service)(nil)

// Service struct to hold dependencies if needed
type Service struct {
	transformers transformer.Set
	scope        Scope
}

// NewService initializes a new Service instance.
func NewService(transformers transformer.Set, scope Scope) *Service {
	return &Service{
		transformers: transformers,
		scope:        scope,
	}
}

// PostV1Enrich handles the POST /v1/enrich endpoint.
func (s *Service) PostV1Enrich(w http.ResponseWriter, r *http.Request) {
	var req api.EnrichmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.clientError(w, http.StatusBadRequest, "Invalid format for enrichment")
		return
	}

	transformationPlugin, ok := s.transformers[transformer.ID(req.Evidence.Source)]
	if !ok {
		// Use fallback
		transformationPlugin = basic.NewBasicTransformer()
	}
	enrichedResponse := Enrich(req.Evidence, transformationPlugin, s.scope)

	s.writeResponse(w, enrichedResponse, http.StatusOK)
}

// ClientError logs error based on its status code and returns the status code in the response.
func (s *Service) clientError(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
	return
}

// ServerError logs the error and a stack trace, and returns a StatusInternalServerError in the response.
func (s *Service) serverError(w http.ResponseWriter, message string) {
	http.Error(w, message, http.StatusInternalServerError)
	return
}

func (s *Service) writeResponse(w http.ResponseWriter, resp api.EnrichmentResponse, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.serverError(w, fmt.Sprintf("failed to write to response: %w", err))
		return
	}
}
