package service

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/complytime/complybeacon/compass/api"

	"github.com/complytime/complybeacon/compass/mapper"
	"github.com/complytime/complybeacon/compass/mapper/plugins/basic"
)

// Service struct to hold dependencies if needed
type Service struct {
	set          mapper.Set
	scope        mapper.Scope
	maxBatchSize int
	version      string
}

// NewService initializes a new Service instance.
func NewService(transformers mapper.Set, scope mapper.Scope) *Service {
	return &Service{
		set:          transformers,
		scope:        scope,
		maxBatchSize: 100, // Default max batch size
		version:      "1.0.0",
	}
}

// PostV1MetadataBatch handles the POST /v1/metadata/batch endpoint.
// Returns static compliance metadata for multiple policy rules.
func (s *Service) PostV1MetadataBatch(c *gin.Context) {
	var req api.BatchMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.Error{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Validate request
	if len(req.Policies) == 0 {
		c.JSON(http.StatusBadRequest, api.Error{
			Code:    http.StatusBadRequest,
			Message: "At least one policy rule ID is required",
		})
		return
	}

	results := make([]api.BatchMetadataResult, len(req.Policies))
	successCount := 0

	for i, policy := range req.Policies {
		// Get the mapper plugin (use basic as fallback)
		mapperPlugin, ok := s.set[mapper.ID("basic")]
		if !ok {
			mapperPlugin = basic.NewBasicMapper()
		}

		result := api.BatchMetadataResult{
			Index:  i,
			Policy: policy,
		}

		// Get metadata for this policy rule
		compliance := mapperPlugin.Map(policy, s.scope)
		result.Compliance = &compliance
		successCount++

		results[i] = result
	}

	// Create response
	response := api.BatchMetadataResponse{
		Results: results,
		Summary: api.BatchSummary{
			Total:   len(req.Policies),
			Success: successCount,
			Failed:  len(req.Policies) - successCount,
		},
	}

	c.JSON(http.StatusOK, response)
}

// PostV1Metadata handles the POST /v1/metadata endpoint.
// It's a handler function for Gin.
func (s *Service) PostV1Metadata(c *gin.Context) {
	var req api.MetadataRequest
	err := c.Bind(&req)
	if err != nil {
		sendCompassError(c, http.StatusBadRequest, "Invalid format for enrichment")
		return
	}

	mapperPlugin, ok := s.set[mapper.ID(req.Policy.PolicyEngineName)]
	if !ok {
		// Use fallback
		log.Printf("WARNING: Policy engine %s not found in mapper set, using basic mapper fallback", req.Policy.PolicyEngineName)
		mapperPlugin = basic.NewBasicMapper()
	}
	compliance := mapperPlugin.Map(req.Policy, s.scope)
	enrichedResponse := api.MetadataResponse{
		Compliance: compliance,
	}

	c.JSON(http.StatusOK, enrichedResponse)
}

// sendCompassError wraps sending of an error in the Error format, and
// handling the failure to marshal that.
func sendCompassError(c *gin.Context, code int32, message string) {
	compassErr := api.Error{
		Code:    code,
		Message: message,
	}
	c.JSON(int(code), compassErr)
}
