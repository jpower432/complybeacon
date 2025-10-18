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
	if len(req.PolicyRuleIds) == 0 {
		c.JSON(http.StatusBadRequest, api.Error{
			Code:    http.StatusBadRequest,
			Message: "At least one policy rule ID is required",
		})
		return
	}

	// Get the mapper plugin (use basic as fallback)
	mapperPlugin, ok := s.set[mapper.ID("basic")]
	if !ok {
		mapperPlugin = basic.NewBasicMapper()
	}

	// Process each policy rule ID
	results := make([]api.BatchMetadataResult, len(req.PolicyRuleIds))
	successCount := 0

	for i, policyRuleId := range req.PolicyRuleIds {
		result := api.BatchMetadataResult{
			Index:       i,
			PolicyRuleId: policyRuleId,
		}

		// Get metadata for this policy rule
		metadata, _ := mapperPlugin.GetMetadata(policyRuleId, s.scope)
		result.Metadata = metadata
		successCount++

		results[i] = result
	}

	// Create response
	response := api.BatchMetadataResponse{
		Results: results,
		Summary: api.BatchSummary{
			Total:   len(req.PolicyRuleIds),
			Success: successCount,
			Failed:  len(req.PolicyRuleIds) - successCount,
		},
	}

	c.JSON(http.StatusOK, response)
}

// PostV1Enrich handles the POST /v1/enrich endpoint.
// It's a handler function for Gin.
func (s *Service) PostV1Enrich(c *gin.Context) {
	var req api.EnrichmentRequest
	err := c.Bind(&req)
	if err != nil {
		sendCompassError(c, http.StatusBadRequest, "Invalid format for enrichment")
		return
	}

	mapperPlugin, ok := s.set[mapper.ID(req.Evidence.PolicyEngineName)]
	if !ok {
		// Use fallback
		log.Printf("WARNING: Policy engine %s not found in mapper set, using basic mapper fallback", req.Evidence.PolicyEngineName)
		mapperPlugin = basic.NewBasicMapper()
	}
	compliance := enrich(req.Evidence, mapperPlugin, s.scope)
	enrichedResponse := api.EnrichmentResponse{
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

// Enrich the raw evidence with risk attributes based on `gemara` semantics.
func enrich(rawEnv api.Evidence, attributeMapper mapper.Mapper, scope mapper.Scope) api.Compliance {
	// Get static metadata
	metadata, enrichmentStatus := attributeMapper.GetMetadata(rawEnv.PolicyRuleId, scope)
	
	// Calculate dynamic status based on current evidence (always recalculated)
	status := attributeMapper.CalculateStatus(rawEnv)
	
	// Combine static metadata with dynamic status
	compliance := api.Compliance{
		Control:          metadata.Control,
		Frameworks:       metadata.Frameworks,
		Risk:             metadata.Risk,
		Status:           status,
		EnrichmentStatus: api.ComplianceEnrichmentStatus(enrichmentStatus),
	}
	
	return compliance
}
