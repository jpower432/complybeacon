package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestCacheableClient_Retrieve(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock batch metadata response
		response := `{
			"results": [
				{
					"index": 0,
					"policyRuleId": "test-policy-123",
					"metadata": {
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
				}
			],
			"summary": {
				"total": 1,
				"success": 1,
				"failed": 0
			}
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}))
	defer server.Close()

	// Create client
	baseClient, err := NewClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create base client: %v", err)
	}

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	// Test evidence
	evidence := &Evidence{
		PolicyRuleId:           "test-policy-123",
		PolicyEngineName:       "test-engine",
		PolicyEvaluationStatus: Passed,
		Timestamp:              time.Now(),
	}

	// First call should hit the server
	enrichment1, err := cacheableClient.Retrieve(context.Background(), evidence)
	if err != nil {
		t.Fatalf("Failed to get enrichment: %v", err)
	}

	if enrichment1.Compliance.Control.Id != "AC-1" {
		t.Errorf("Expected control 'AC-1', got '%s'", enrichment1.Compliance.Control.Id)
	}

	// Second call should hit the cache
	enrichment2, err := cacheableClient.Retrieve(context.Background(), evidence)
	if err != nil {
		t.Fatalf("Failed to get enrichment from cache: %v", err)
	}

	if enrichment2.Compliance.Control.Id != "AC-1" {
		t.Errorf("Expected control 'AC-1' from cache, got '%s'", enrichment2.Compliance.Control.Id)
	}

	// Verify they have the same content (cached)
	if enrichment1.Compliance.Control.Id != enrichment2.Compliance.Control.Id {
		t.Error("Expected cached response to return the same content")
	}
}

func TestCacheableClient_Prefetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := `{
			"results": [
				{
					"index": 0,
					"policyRuleId": "test-policy-123",
					"metadata": {
						"control": {
							"id": "AC-1",
							"catalogId": "NIST-800-53",
							"category": "Access Control"
						},
						"frameworks": {
							"requirements": [],
							"frameworks": []
						},
						"enrichmentStatus": "success"
					}
				},
				{
					"index": 1,
					"policyRuleId": "test-policy-456",
					"metadata": {
						"control": {
							"id": "AC-2",
							"catalogId": "NIST-800-53",
							"category": "Access Control"
						},
						"frameworks": {
							"requirements": [],
							"frameworks": []
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
	if err != nil {
		t.Fatalf("Failed to create base client: %v", err)
	}

	cacheableClient := NewCacheableClient(baseClient, zap.NewNop())

	// Test evidence list for prefetch
	evidenceList := []Evidence{
		{
			PolicyRuleId:           "test-policy-123",
			PolicyEngineName:       "test-engine",
			PolicyEvaluationStatus: Passed,
			Timestamp:              time.Now(),
		},
		{
			PolicyRuleId:           "test-policy-456",
			PolicyEngineName:       "test-engine-2",
			PolicyEvaluationStatus: Passed,
			Timestamp:              time.Now(),
		},
	}

	// Test prefetch functionality
	err = cacheableClient.Prefetch(context.Background(), evidenceList)
	if err != nil {
		t.Fatalf("Failed to prefetch enrichment data: %v", err)
	}

	// Verify that the data was cached by retrieving it
	evidence := &Evidence{
		PolicyRuleId:           "test-policy-123",
		PolicyEngineName:       "test-engine",
		PolicyEvaluationStatus: Passed,
		Timestamp:              time.Now(),
	}

	enrichment, err := cacheableClient.Retrieve(context.Background(), evidence)
	if err != nil {
		t.Fatalf("Failed to retrieve cached enrichment: %v", err)
	}

	if enrichment.Compliance.Control.Id != "AC-1" {
		t.Errorf("Expected control 'AC-1', got '%s'", enrichment.Compliance.Control.Id)
	}
}
