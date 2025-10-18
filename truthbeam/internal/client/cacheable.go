package client

import (
	"context"
	"fmt"
	"sync"

	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
)

// CacheableClient wraps the basic client with caching and prefetching capabilities
type CacheableClient struct {
	client *Client
	cache  *cache.Cache
	mu     sync.Mutex
	logger *zap.Logger
}

// NewCacheableClient creates a new enriched client with caching capabilities
func NewCacheableClient(client *Client, logger *zap.Logger) *CacheableClient {
	ec := &CacheableClient{
		client: client,
		// Set Cache TTL
		cache:  cache.New(cache.NoExpiration, cache.NoExpiration),
		logger: logger,
	}
	return ec
}

// Retrieve gets compliance data for evidence, using cached metadata and calculating status locally
func (c *CacheableClient) Retrieve(ctx context.Context, evidence *Evidence) (EnrichmentResponse, error) {
	// Check if metadata is in the cache
	var metadata *ComplianceMetadata
	if value, found := c.cache.Get(evidence.PolicyRuleId); found {
		metadata = value.(*ComplianceMetadata)
	} else {
		// Fetch metadata from batch API
		var err error
		metadata, err = c.fetchMetadata(ctx, evidence.PolicyRuleId)
		if err != nil {
			return EnrichmentResponse{}, fmt.Errorf("failed to fetch metadata: %w", err)
		}
		// Cache the metadata
		c.cache.Set(evidence.PolicyRuleId, metadata, cache.NoExpiration)
	}

	// Calculate status locally based on current evidence
	status := c.calculateStatus(evidence)

	// Combine metadata with calculated status
	compliance := Compliance{
		Control:          metadata.Control,
		Frameworks:       metadata.Frameworks,
		Risk:             metadata.Risk,
		Status:           &status,
		EnrichmentStatus: ComplianceEnrichmentStatus(metadata.EnrichmentStatus),
	}

	return EnrichmentResponse{Compliance: compliance}, nil
}

// Prefetch prefetches metadata for a list of policy contexts using batch API
func (c *CacheableClient) Prefetch(ctx context.Context, evidenceList []Evidence) error {
	c.logger.Info("Starting prefetch of metadata",
		zap.Int("count", len(evidenceList)),
	)

	// Extract unique policy rule IDs
	policyRuleIds := make([]string, 0)
	seen := make(map[string]bool)
	for _, evidence := range evidenceList {
		if !seen[evidence.PolicyRuleId] {
			policyRuleIds = append(policyRuleIds, evidence.PolicyRuleId)
			seen[evidence.PolicyRuleId] = true
		}
	}

	if len(policyRuleIds) == 0 {
		c.logger.Info("No unique policy rule IDs to prefetch")
		return nil
	}

	// Fetch metadata in batches
	batchSize := 50 // Process in batches of 50
	for i := 0; i < len(policyRuleIds); i += batchSize {
		end := i + batchSize
		if end > len(policyRuleIds) {
			end = len(policyRuleIds)
		}
		
		batch := policyRuleIds[i:end]
		err := c.prefetchBatch(ctx, batch)
		if err != nil {
			c.logger.Warn("Failed to prefetch batch",
				zap.Int("batch_start", i),
				zap.Int("batch_size", len(batch)),
				zap.Error(err),
			)
		}
	}

	c.logger.Info("Completed prefetch of metadata")
	return nil
}

// prefetchBatch fetches metadata for a batch of policy rule IDs
func (c *CacheableClient) prefetchBatch(ctx context.Context, policyRuleIds []string) error {
	req := BatchMetadataRequest{
		PolicyRuleIds: policyRuleIds,
	}

	resp, err := c.callBatchMetadata(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to call batch metadata API: %w", err)
	}

	// Cache the results
	for _, result := range resp.Results {
		if result.Error == nil && result.Metadata != nil {
			c.cache.Set(result.PolicyRuleId, result.Metadata, cache.NoExpiration)
		}
	}

	return nil
}

// fetchMetadata fetches metadata for a single policy rule using the batch API
func (c *CacheableClient) fetchMetadata(ctx context.Context, policyRuleId string) (*ComplianceMetadata, error) {
	req := BatchMetadataRequest{
		PolicyRuleIds: []string{policyRuleId},
	}
	
	resp, err := c.callBatchMetadata(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to call batch metadata API: %w", err)
	}

	if len(resp.Results) == 0 {
		return nil, fmt.Errorf("no metadata returned for policy rule %s", policyRuleId)
	}

	result := resp.Results[0]
	if result.Error != nil {
		return nil, fmt.Errorf("error fetching metadata for policy rule %s: %s", policyRuleId, result.Error.Message)
	}

	if result.Metadata == nil {
		return nil, fmt.Errorf("no metadata found for policy rule %s", policyRuleId)
	}

	return result.Metadata, nil
}

// calculateStatus calculates compliance status based on evidence
func (c *CacheableClient) calculateStatus(evidence *Evidence) ComplianceStatus {
	// Map EvidencePolicyEvaluationStatus to ComplianceStatus
	switch evidence.PolicyEvaluationStatus {
	case Passed:
		return COMPLIANT
	case Failed:
		return NONCOMPLIANT
	case NotApplicable:
		return NOTAPPLICABLE
	default:
		return UNKNOWN
	}
}

// callBatchMetadata makes the actual batch metadata API call
func (c *CacheableClient) callBatchMetadata(ctx context.Context, req BatchMetadataRequest) (*BatchMetadataResponse, error) {
	resp, err := c.client.PostV1MetadataBatch(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the response
	parsedResp, err := ParsePostV1MetadataBatchResponse(resp)
	if err != nil {
		return nil, err
	}

	if parsedResp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	return parsedResp.JSON200, nil
}
