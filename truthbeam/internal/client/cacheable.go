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

// Retrieve gets compliance data for evidence, using cached metadata by default.
func (c *CacheableClient) Retrieve(ctx context.Context, policy Policy) (Compliance, error) {
	var metadata Compliance
	if value, found := c.cache.Get(policy.PolicyRuleId); found {
		metadata = value.(Compliance)
	} else {
		// Fetch metadata from API
		var err error
		metadata, err = c.fetchMetadata(ctx, policy)
		if err != nil {
			return Compliance{}, fmt.Errorf("failed to fetch metadata: %w", err)
		}
		c.cache.Set(policy.PolicyRuleId, metadata, cache.NoExpiration)
	}

	compliance := Compliance{
		Control:          metadata.Control,
		Frameworks:       metadata.Frameworks,
		Risk:             metadata.Risk,
		EnrichmentStatus: metadata.EnrichmentStatus,
	}

	return compliance, nil
}

// Prefetch prefetches metadata for a list of policy contexts using batch API
func (c *CacheableClient) Prefetch(ctx context.Context, policies []Policy) error {
	c.logger.Info("Starting prefetch of metadata",
		zap.Int("count", len(policies)),
	)

	if len(policies) == 0 {
		c.logger.Info("No policy data to prefetch")
		return nil
	}

	// Fetch metadata in batches
	batchSize := 50 // Process in batches of 50
	for i := 0; i < len(policies); i += batchSize {
		end := i + batchSize
		if end > len(policies) {
			end = len(policies)
		}

		batch := policies[i:end]
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
func (c *CacheableClient) prefetchBatch(ctx context.Context, policies []Policy) error {
	req := BatchMetadataRequest{
		Policies: policies,
	}

	resp, err := c.callBatchMetadata(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to call batch metadata API: %w", err)
	}

	for _, result := range resp.Results {
		if result.Error == nil && result.Compliance != nil {
			c.cache.Set(result.Policy.PolicyRuleId, *result.Compliance, cache.NoExpiration)
		}
	}

	return nil
}

// fetchMetadata fetches metadata for a single policy rule using the API
func (c *CacheableClient) fetchMetadata(ctx context.Context, policy Policy) (Compliance, error) {
	req := MetadataRequest{
		Policy: policy,
	}

	resp, err := c.callMetadata(ctx, req)
	if err != nil {
		return Compliance{}, fmt.Errorf("failed to call batch metadata API: %w", err)
	}

	return resp.Compliance, nil
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

// callBatchMetadata makes the actual batch metadata API call
func (c *CacheableClient) callMetadata(ctx context.Context, req MetadataRequest) (*MetadataResponse, error) {
	resp, err := c.client.PostV1Metadata(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the response
	parsedResp, err := ParsePostV1MetadataResponse(resp)
	if err != nil {
		return nil, err
	}

	if parsedResp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	return parsedResp.JSON200, nil
}
