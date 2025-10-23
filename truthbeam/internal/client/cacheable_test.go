package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestCacheableClient_Retrieve(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock single metadata response
		response := `{
			"compliance": {
				"control": {
					"id": "AC-1",
					"catalogId": "NIST-800-53",
					"category": "Access Control",
					"remediationDescription": "Implement proper access controls"
				},
				"frameworks": {
					"requirements": ["REQ-001", "REQ-002"],
					"frameworks": ["NIST-800-53", "ISO-27001"]
				},
				"enrichmentStatus": "success"
			}
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	defer server.Close()

	// Create client
	baseClient, err := NewClient(server.URL)
	assert.NoError(t, err)

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	// Test policy
	policy := Policy{
		PolicyRuleId:     "test-policy-123",
		PolicyEngineName: "test-engine",
	}

	// First call should hit the server
	compliance1, err := cacheableClient.Retrieve(context.Background(), policy)
	assert.NoError(t, err)
	assert.Equal(t, "AC-1", compliance1.Control.Id)
	assert.Equal(t, "NIST-800-53", compliance1.Control.CatalogId)
	assert.Equal(t, "Access Control", compliance1.Control.Category)
	assert.NotNil(t, compliance1.Control.RemediationDescription)
	assert.Equal(t, "Implement proper access controls", *compliance1.Control.RemediationDescription)
	assert.Contains(t, compliance1.Frameworks.Requirements, "REQ-001")
	assert.Contains(t, compliance1.Frameworks.Frameworks, "NIST-800-53")
	assert.Equal(t, "success", string(compliance1.EnrichmentStatus))

	// Second call should hit the cache
	compliance2, err := cacheableClient.Retrieve(context.Background(), policy)
	assert.NoError(t, err)
	assert.Equal(t, "AC-1", compliance2.Control.Id)

	// Verify they have the same content (cached)
	assert.Equal(t, compliance1.Control.Id, compliance2.Control.Id)
	assert.Equal(t, compliance1.Control.CatalogId, compliance2.Control.CatalogId)
	assert.Equal(t, compliance1.EnrichmentStatus, compliance2.EnrichmentStatus)
}

func TestCacheableClient_Prefetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := `{
			"results": [
				{
					"index": 0,
					"policy": {
						"policyRuleId": "test-policy-123",
						"policyEngineName": "test-engine"
					},
					"compliance": {
						"control": {
							"id": "AC-1",
							"catalogId": "NIST-800-53",
							"category": "Access Control"
						},
						"frameworks": {
							"requirements": ["REQ-001"],
							"frameworks": ["NIST-800-53"]
						},
						"enrichmentStatus": "success"
					}
				},
				{
					"index": 1,
					"policy": {
						"policyRuleId": "test-policy-456",
						"policyEngineName": "test-engine-2"
					},
					"compliance": {
						"control": {
							"id": "AC-2",
							"catalogId": "NIST-800-53",
							"category": "Access Control"
						},
						"frameworks": {
							"requirements": ["REQ-002"],
							"frameworks": ["NIST-800-53"]
						},
						"enrichmentStatus": "success"
					}
				}
			],
			"summary": {
				"total": 2,
				"success": 2,
				"failed": 0
			}
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	defer server.Close()

	baseClient, err := NewClient(server.URL)
	assert.NoError(t, err)

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	// Test policy list for prefetch
	policyList := []Policy{
		{
			PolicyRuleId:     "test-policy-123",
			PolicyEngineName: "test-engine",
		},
		{
			PolicyRuleId:     "test-policy-456",
			PolicyEngineName: "test-engine-2",
		},
	}

	// Test prefetch functionality
	err = cacheableClient.Prefetch(context.Background(), policyList)
	assert.NoError(t, err)

	// Verify that the data was cached by retrieving it
	policy := Policy{
		PolicyRuleId:     "test-policy-123",
		PolicyEngineName: "test-engine",
	}

	compliance, err := cacheableClient.Retrieve(context.Background(), policy)
	assert.NoError(t, err)
	assert.Equal(t, "AC-1", compliance.Control.Id)
	assert.Equal(t, "NIST-800-53", compliance.Control.CatalogId)
	assert.Equal(t, "Access Control", compliance.Control.Category)
	assert.Contains(t, compliance.Frameworks.Requirements, "REQ-001")
	assert.Contains(t, compliance.Frameworks.Frameworks, "NIST-800-53")
	assert.Equal(t, "success", string(compliance.EnrichmentStatus))
}

func TestCacheableClient_PrefetchEmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Server should not be called for empty policy list")
	}))
	defer server.Close()

	baseClient, err := NewClient(server.URL)
	assert.NoError(t, err)

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	// Test prefetch with empty list
	err = cacheableClient.Prefetch(context.Background(), []Policy{})
	assert.NoError(t, err)
}

func TestCacheableClient_RetrieveError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	baseClient, err := NewClient(server.URL)
	assert.NoError(t, err)

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	policy := Policy{
		PolicyRuleId:     "test-policy-123",
		PolicyEngineName: "test-engine",
	}

	// Test retrieve with server error
	_, err = cacheableClient.Retrieve(context.Background(), policy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch metadata")
}

func TestCacheableClient_PrefetchBatchError(t *testing.T) {
	// Create a mock server that returns an error for batch requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	baseClient, err := NewClient(server.URL)
	assert.NoError(t, err)

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	policyList := []Policy{
		{
			PolicyRuleId:     "test-policy-123",
			PolicyEngineName: "test-engine",
		},
	}

	// Test prefetch with server error - should not return error but log warning
	err = cacheableClient.Prefetch(context.Background(), policyList)
	assert.NoError(t, err) // Prefetch should handle errors gracefully
}

func TestCacheableClient_NewCacheableClient(t *testing.T) {
	baseClient, err := NewClient("http://localhost:8080")
	assert.NoError(t, err)

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())
	assert.NotNil(t, cacheableClient)
	assert.Equal(t, baseClient, cacheableClient.client)
	assert.NotNil(t, cacheableClient.cache)
	assert.NotNil(t, cacheableClient.logger)
}
