package applier

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/complytime/complybeacon/truthbeam/internal/client"
)

func TestApplier_ExtractEvidence(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	tests := []struct {
		name             string
		attributes       map[string]string
		expectedError    bool
		expectedEvidence *client.Evidence
	}{
		{
			name: "valid evidence extraction",
			attributes: map[string]string{
				client.POLICY_RULE_ID:           "test-rule-123",
				client.POLICY_ENGINE_NAME:       "test-engine",
				client.POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: false,
			expectedEvidence: &client.Evidence{
				PolicyRuleId:           "test-rule-123",
				PolicyEngineName:       "test-engine",
				PolicyEvaluationStatus: client.Passed,
			},
		},
		{
			name: "missing policy rule id",
			attributes: map[string]string{
				client.POLICY_ENGINE_NAME:       "test-engine",
				client.POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: true,
		},
		{
			name: "missing policy engine name",
			attributes: map[string]string{
				client.POLICY_RULE_ID:           "test-rule-123",
				client.POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: true,
		},
		{
			name: "missing policy evaluation result",
			attributes: map[string]string{
				client.POLICY_RULE_ID:     "test-rule-123",
				client.POLICY_ENGINE_NAME: "test-engine",
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test log record
			logRecord := plog.NewLogRecord()
			logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

			// Set attributes
			attrs := logRecord.Attributes()
			for key, value := range tt.attributes {
				attrs.PutStr(key, value)
			}

			// Extract evidence
			evidence, err := applier.ExtractEvidence(logRecord)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to extract evidence: %v", err)
			}

			// Verify evidence fields
			if evidence.PolicyRuleId != tt.expectedEvidence.PolicyRuleId {
				t.Errorf("Expected PolicyRuleId '%s', got '%s'", tt.expectedEvidence.PolicyRuleId, evidence.PolicyRuleId)
			}
			if evidence.PolicyEngineName != tt.expectedEvidence.PolicyEngineName {
				t.Errorf("Expected PolicyEngineName '%s', got '%s'", tt.expectedEvidence.PolicyEngineName, evidence.PolicyEngineName)
			}
			if evidence.PolicyEvaluationStatus != tt.expectedEvidence.PolicyEvaluationStatus {
				t.Errorf("Expected PolicyEvaluationStatus '%s', got '%s'", tt.expectedEvidence.PolicyEvaluationStatus, evidence.PolicyEvaluationStatus)
			}
		})
	}
}

func TestApplier_ApplyEnrichment(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	tests := []struct {
		name          string
		enrichment    *client.EnrichmentResponse
		expectedError bool
		expectedAttrs map[string]string
	}{
		{
			name: "valid enrichment with all fields",
			enrichment: &client.EnrichmentResponse{
				Compliance: client.Compliance{
					Control: client.ComplianceControl{
						Id:                     "AC-1",
						CatalogId:              "NIST-800-53",
						Category:               "Access Control",
						RemediationDescription: stringPtr("Implement proper access controls"),
					},
					Frameworks: client.ComplianceFrameworks{
						Requirements: []string{"REQ-001", "REQ-002"},
						Frameworks:   []string{"NIST-800-53", "ISO-27001"},
					},
					Status: func() *client.ComplianceStatus { s := client.COMPLIANT; return &s }(),
				},
			},
			expectedError: false,
			expectedAttrs: map[string]string{
				client.COMPLIANCE_STATUS:                  "COMPLIANT",
				client.COMPLIANCE_CONTROL_ID:              "AC-1",
				client.COMPLIANCE_CONTROL_CATALOG_ID:      "NIST-800-53",
				client.COMPLIANCE_CONTROL_CATEGORY:        "Access Control",
				client.COMPLIANCE_REMEDIATION_DESCRIPTION: "Implement proper access controls",
			},
		},
		{
			name: "enrichment without remediation description",
			enrichment: &client.EnrichmentResponse{
				Compliance: client.Compliance{
					Control: client.ComplianceControl{
						Id:        "AC-2",
						CatalogId: "NIST-800-53",
						Category:  "Access Control",
					},
					Frameworks: client.ComplianceFrameworks{
						Requirements: []string{"REQ-003"},
						Frameworks:   []string{"NIST-800-53"},
					},
					Status: func() *client.ComplianceStatus { s := client.NONCOMPLIANT; return &s }(),
				},
			},
			expectedError: false,
			expectedAttrs: map[string]string{
				client.COMPLIANCE_STATUS:             "NON_COMPLIANT",
				client.COMPLIANCE_CONTROL_ID:         "AC-2",
				client.COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				client.COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
		},
		{
			name:          "nil enrichment response",
			enrichment:    nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test log record
			logRecord := plog.NewLogRecord()
			attrs := logRecord.Attributes()

			// Apply enrichment
			err := applier.ApplyEnrichment(nil, logRecord, tt.enrichment)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to apply enrichment: %v", err)
			}

			// Verify applied attributes
			for key, expectedValue := range tt.expectedAttrs {
				val, ok := attrs.Get(key)
				if !ok {
					t.Errorf("Expected attribute '%s' to be set", key)
					continue
				}
				if val.Str() != expectedValue {
					t.Errorf("Expected attribute '%s' to be '%s', got '%s'", key, expectedValue, val.Str())
				}
			}

			// Verify array attributes
			if tt.enrichment != nil {
				// Check requirements array
				if reqVal, ok := attrs.Get(client.COMPLIANCE_REQUIREMENTS); ok {
					reqSlice := reqVal.Slice()
					if reqSlice.Len() != len(tt.enrichment.Compliance.Frameworks.Requirements) {
						t.Errorf("Expected %d requirements, got %d", len(tt.enrichment.Compliance.Frameworks.Requirements), reqSlice.Len())
					}
					for i := 0; i < reqSlice.Len(); i++ {
						if reqSlice.At(i).Str() != tt.enrichment.Compliance.Frameworks.Requirements[i] {
							t.Errorf("Expected requirement[%d] to be '%s', got '%s'", i, tt.enrichment.Compliance.Frameworks.Requirements[i], reqSlice.At(i).Str())
						}
					}
				}

				// Check frameworks array
				if fwVal, ok := attrs.Get(client.COMPLIANCE_FRAMEWORKS); ok {
					fwSlice := fwVal.Slice()
					if fwSlice.Len() != len(tt.enrichment.Compliance.Frameworks.Frameworks) {
						t.Errorf("Expected %d frameworks, got %d", len(tt.enrichment.Compliance.Frameworks.Frameworks), fwSlice.Len())
					}
					for i := 0; i < fwSlice.Len(); i++ {
						if fwSlice.At(i).Str() != tt.enrichment.Compliance.Frameworks.Frameworks[i] {
							t.Errorf("Expected framework[%d] to be '%s', got '%s'", i, tt.enrichment.Compliance.Frameworks.Frameworks[i], fwSlice.At(i).Str())
						}
					}
				}
			}
		})
	}
}

func TestApplier_ApplyEnrichment_EdgeCases(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	t.Run("enrichment with empty arrays", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		attrs := logRecord.Attributes()

		enrichment := &client.EnrichmentResponse{
			Compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-3",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{},
					Frameworks:   []string{},
				},
				Status: func() *client.ComplianceStatus { s := client.UNKNOWN; return &s }(),
			},
		}

		err := applier.ApplyEnrichment(nil, logRecord, enrichment)
		if err != nil {
			t.Fatalf("Failed to apply enrichment: %v", err)
		}

		// Verify basic attributes are still set
		if val, ok := attrs.Get(client.COMPLIANCE_STATUS); !ok || val.Str() != "UNKNOWN" {
			t.Errorf("Expected compliance status 'UNKNOWN', got '%s'", val.Str())
		}

		// Verify empty arrays are handled
		if reqVal, ok := attrs.Get(client.COMPLIANCE_REQUIREMENTS); ok {
			if reqVal.Slice().Len() != 0 {
				t.Errorf("Expected empty requirements array, got %d items", reqVal.Slice().Len())
			}
		}

		if fwVal, ok := attrs.Get(client.COMPLIANCE_FRAMEWORKS); ok {
			if fwVal.Slice().Len() != 0 {
				t.Errorf("Expected empty frameworks array, got %d items", fwVal.Slice().Len())
			}
		}
	})

	t.Run("enrichment with nil status", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		attrs := logRecord.Attributes()

		enrichment := &client.EnrichmentResponse{
			Compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-4",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{"REQ-004"},
					Frameworks:   []string{"NIST-800-53"},
				},
				Status: nil, // nil status
			},
		}

		err := applier.ApplyEnrichment(nil, logRecord, enrichment)
		if err != nil {
			t.Fatalf("Failed to apply enrichment: %v", err)
		}

		// Status should be empty string when nil
		if val, ok := attrs.Get(client.COMPLIANCE_STATUS); !ok || val.Str() != "" {
			t.Errorf("Expected empty compliance status, got '%s'", val.Str())
		}
	})
}

func TestApplier_ExtractEvidence_EdgeCases(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	t.Run("log record with empty attributes", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

		_, err := applier.ExtractEvidence(logRecord)
		if err == nil {
			t.Error("Expected error for empty attributes, got none")
		}
	})

	t.Run("log record with invalid evaluation status", func(t *testing.T) {
		logRecord := plog.NewLogRecord()
		logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Now()))

		attrs := logRecord.Attributes()
		attrs.PutStr(client.POLICY_RULE_ID, "test-rule-123")
		attrs.PutStr(client.POLICY_ENGINE_NAME, "test-engine")
		attrs.PutStr(client.POLICY_EVALUATION_RESULT, "invalid-status")

		evidence, err := applier.ExtractEvidence(logRecord)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		// Should still extract the evidence even with invalid status
		if evidence.PolicyRuleId != "test-rule-123" {
			t.Errorf("Expected PolicyRuleId 'test-rule-123', got '%s'", evidence.PolicyRuleId)
		}
		if evidence.PolicyEvaluationStatus != "invalid-status" {
			t.Errorf("Expected PolicyEvaluationStatus 'invalid-status', got '%s'", evidence.PolicyEvaluationStatus)
		}
	})
}

func stringPtr(s string) *string {
	return &s
}
