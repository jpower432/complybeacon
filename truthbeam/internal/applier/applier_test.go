package applier

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/complytime/complybeacon/truthbeam/internal/client"
)

func TestApplier_Extract(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	tests := []struct {
		name           string
		attributes     map[string]string
		expectedError  bool
		expectedPolicy *client.Policy
		expectedStatus string
		errorContains  string
	}{
		{
			name: "valid evidence extraction with Passed status",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-123",
				POLICY_ENGINE_NAME:       "test-engine",
				POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "test-rule-123",
				PolicyEngineName: "test-engine",
			},
			expectedStatus: "Passed",
		},
		{
			name: "valid evidence extraction with Failed status",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-456",
				POLICY_ENGINE_NAME:       "test-engine-2",
				POLICY_EVALUATION_RESULT: "Failed",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "test-rule-456",
				PolicyEngineName: "test-engine-2",
			},
			expectedStatus: "Failed",
		},
		{
			name: "valid evidence extraction with Not Applicable status",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-789",
				POLICY_ENGINE_NAME:       "test-engine-3",
				POLICY_EVALUATION_RESULT: "Not Applicable",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "test-rule-789",
				PolicyEngineName: "test-engine-3",
			},
			expectedStatus: "Not Applicable",
		},
		{
			name: "valid evidence extraction with Not Run status",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-999",
				POLICY_ENGINE_NAME:       "test-engine-4",
				POLICY_EVALUATION_RESULT: "Not Run",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "test-rule-999",
				PolicyEngineName: "test-engine-4",
			},
			expectedStatus: "Not Run",
		},
		{
			name: "valid evidence extraction with Unknown status",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-unknown",
				POLICY_ENGINE_NAME:       "test-engine-unknown",
				POLICY_EVALUATION_RESULT: "Unknown",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "test-rule-unknown",
				PolicyEngineName: "test-engine-unknown",
			},
			expectedStatus: "Unknown",
		},
		{
			name: "missing policy rule id",
			attributes: map[string]string{
				POLICY_ENGINE_NAME:       "test-engine",
				POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: true,
			errorContains: "missing required attribute",
		},
		{
			name: "missing policy engine name",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-123",
				POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: true,
			errorContains: "missing required attribute",
		},
		{
			name: "missing policy evaluation result",
			attributes: map[string]string{
				POLICY_RULE_ID:     "test-rule-123",
				POLICY_ENGINE_NAME: "test-engine",
			},
			expectedError: true,
			errorContains: "missing required attributes",
		},
		{
			name: "empty policy rule id",
			attributes: map[string]string{
				POLICY_RULE_ID:           "",
				POLICY_ENGINE_NAME:       "test-engine",
				POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "",
				PolicyEngineName: "test-engine",
			},
			expectedStatus: "Passed",
		},
		{
			name: "empty policy engine name",
			attributes: map[string]string{
				POLICY_RULE_ID:           "test-rule-123",
				POLICY_ENGINE_NAME:       "",
				POLICY_EVALUATION_RESULT: "Passed",
			},
			expectedError: false,
			expectedPolicy: &client.Policy{
				PolicyRuleId:     "test-rule-123",
				PolicyEngineName: "",
			},
			expectedStatus: "Passed",
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
			policy, status, err := applier.Extract(logRecord)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, policy)
			assert.Equal(t, tt.expectedPolicy.PolicyRuleId, policy.PolicyRuleId)
			assert.Equal(t, tt.expectedPolicy.PolicyEngineName, policy.PolicyEngineName)
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestApplier_Apply(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	tests := []struct {
		name           string
		compliance     client.Compliance
		status         string
		expectedError  bool
		expectedAttrs  map[string]string
		expectedArrays map[string][]string
		errorContains  string
	}{
		{
			name: "valid enrichment with all fields - Passed status",
			compliance: client.Compliance{
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
				EnrichmentStatus: client.Success,
				Risk: &client.ComplianceRisk{
					Level: riskLevelPtr("High"),
				},
			},
			status:        "Passed",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:                  "COMPLIANT",
				COMPLIANCE_ENRICHMENT_STATUS:       "success",
				COMPLIANCE_CONTROL_ID:              "AC-1",
				COMPLIANCE_CONTROL_CATALOG_ID:      "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:        "Access Control",
				COMPLIANCE_REMEDIATION_DESCRIPTION: "Implement proper access controls",
				COMPLIANCE_RISK_LEVEL:              "High",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {"REQ-001", "REQ-002"},
				COMPLIANCE_FRAMEWORKS:   {"NIST-800-53", "ISO-27001"},
			},
		},
		{
			name: "valid enrichment with Failed status",
			compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-2",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{"REQ-003"},
					Frameworks:   []string{"NIST-800-53"},
				},
				EnrichmentStatus: client.Success,
			},
			status:        "Failed",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:             "NON_COMPLIANT",
				COMPLIANCE_ENRICHMENT_STATUS:  "success",
				COMPLIANCE_CONTROL_ID:         "AC-2",
				COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {"REQ-003"},
				COMPLIANCE_FRAMEWORKS:   {"NIST-800-53"},
			},
		},
		{
			name: "valid enrichment with Not Applicable status",
			compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-3",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{},
					Frameworks:   []string{},
				},
				EnrichmentStatus: client.Success,
			},
			status:        "Not Applicable",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:             "NOT_APPLICABLE",
				COMPLIANCE_ENRICHMENT_STATUS:  "success",
				COMPLIANCE_CONTROL_ID:         "AC-3",
				COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {},
				COMPLIANCE_FRAMEWORKS:   {},
			},
		},
		{
			name: "valid enrichment with Not Run status",
			compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-4",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{},
					Frameworks:   []string{},
				},
				EnrichmentStatus: client.Success,
			},
			status:        "Not Run",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:             "NOT_APPLICABLE",
				COMPLIANCE_ENRICHMENT_STATUS:  "success",
				COMPLIANCE_CONTROL_ID:         "AC-4",
				COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {},
				COMPLIANCE_FRAMEWORKS:   {},
			},
		},
		{
			name: "valid enrichment with Unknown status",
			compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-5",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{},
					Frameworks:   []string{},
				},
				EnrichmentStatus: client.Success,
			},
			status:        "Unknown",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:             "UNKNOWN",
				COMPLIANCE_ENRICHMENT_STATUS:  "success",
				COMPLIANCE_CONTROL_ID:         "AC-5",
				COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {},
				COMPLIANCE_FRAMEWORKS:   {},
			},
		},
		{
			name: "enrichment with unmapped status",
			compliance: client.Compliance{
				EnrichmentStatus: client.Unmapped,
			},
			status:        "Passed",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:            "COMPLIANT",
				COMPLIANCE_ENRICHMENT_STATUS: "unmapped",
			},
			expectedArrays: map[string][]string{},
		},
		{
			name: "enrichment without remediation description",
			compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-6",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{"REQ-004"},
					Frameworks:   []string{"NIST-800-53"},
				},
				EnrichmentStatus: client.Success,
			},
			status:        "Failed",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:             "NON_COMPLIANT",
				COMPLIANCE_ENRICHMENT_STATUS:  "success",
				COMPLIANCE_CONTROL_ID:         "AC-6",
				COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {"REQ-004"},
				COMPLIANCE_FRAMEWORKS:   {"NIST-800-53"},
			},
		},
		{
			name: "enrichment without risk level",
			compliance: client.Compliance{
				Control: client.ComplianceControl{
					Id:        "AC-7",
					CatalogId: "NIST-800-53",
					Category:  "Access Control",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{},
					Frameworks:   []string{},
				},
				EnrichmentStatus: client.Success,
				Risk:             &client.ComplianceRisk{},
			},
			status:        "Passed",
			expectedError: false,
			expectedAttrs: map[string]string{
				COMPLIANCE_STATUS:             "COMPLIANT",
				COMPLIANCE_ENRICHMENT_STATUS:  "success",
				COMPLIANCE_CONTROL_ID:         "AC-7",
				COMPLIANCE_CONTROL_CATALOG_ID: "NIST-800-53",
				COMPLIANCE_CONTROL_CATEGORY:   "Access Control",
			},
			expectedArrays: map[string][]string{
				COMPLIANCE_REQUIREMENTS: {},
				COMPLIANCE_FRAMEWORKS:   {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test log record
			logRecord := plog.NewLogRecord()
			attrs := logRecord.Attributes()

			// Apply enrichment
			err := applier.Apply(logRecord, tt.compliance, tt.status)

			if tt.expectedError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			require.NoError(t, err)

			// Verify applied attributes
			for key, expectedValue := range tt.expectedAttrs {
				val, ok := attrs.Get(key)
				assert.True(t, ok, "Expected attribute '%s' to be set", key)
				if ok {
					assert.Equal(t, expectedValue, val.Str(), "Attribute '%s' should have value '%s'", key, expectedValue)
				}
			}

			// Verify array attributes
			for arrayKey, expectedArray := range tt.expectedArrays {
				val, ok := attrs.Get(arrayKey)
				if len(expectedArray) == 0 {
					// For empty arrays, the attribute might not be set
					continue
				}
				assert.True(t, ok, "Expected array attribute '%s' to be set", arrayKey)
				if ok {
					slice := val.Slice()
					assert.Equal(t, len(expectedArray), slice.Len(), "Array '%s' should have %d elements", arrayKey, len(expectedArray))
					for i, expectedValue := range expectedArray {
						if i < slice.Len() {
							assert.Equal(t, expectedValue, slice.At(i).Str(), "Array '%s'[%d] should be '%s'", arrayKey, i, expectedValue)
						}
					}
				}
			}
		})
	}
}

func TestApplier_StatusMapping(t *testing.T) {
	tests := []struct {
		name           string
		inputStatus    string
		expectedStatus string
	}{
		{
			name:           "Passed maps to COMPLIANT",
			inputStatus:    "Passed",
			expectedStatus: "COMPLIANT",
		},
		{
			name:           "Failed maps to NON_COMPLIANT",
			inputStatus:    "Failed",
			expectedStatus: "NON_COMPLIANT",
		},
		{
			name:           "Not Applicable maps to NOT_APPLICABLE",
			inputStatus:    "Not Applicable",
			expectedStatus: "NOT_APPLICABLE",
		},
		{
			name:           "Not Run maps to NOT_APPLICABLE",
			inputStatus:    "Not Run",
			expectedStatus: "NOT_APPLICABLE",
		},
		{
			name:           "Unknown maps to UNKNOWN",
			inputStatus:    "Unknown",
			expectedStatus: "UNKNOWN",
		},
		{
			name:           "Empty string maps to UNKNOWN",
			inputStatus:    "",
			expectedStatus: "UNKNOWN",
		},
		{
			name:           "Invalid status maps to UNKNOWN",
			inputStatus:    "InvalidStatus",
			expectedStatus: "UNKNOWN",
		},
	}

	applier := NewApplier(zap.NewNop())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test log record
			logRecord := plog.NewLogRecord()
			attrs := logRecord.Attributes()

			// Set up minimal compliance data
			compliance := client.Compliance{
				Control: client.ComplianceControl{
					Id:        "TEST-1",
					CatalogId: "TEST-CATALOG",
					Category:  "Test Category",
				},
				Frameworks: client.ComplianceFrameworks{
					Requirements: []string{},
					Frameworks:   []string{},
				},
				EnrichmentStatus: client.Success,
			}

			// Apply enrichment
			err := applier.Apply(logRecord, compliance, tt.inputStatus)
			require.NoError(t, err)

			// Verify the status mapping
			val, ok := attrs.Get(COMPLIANCE_STATUS)
			require.True(t, ok, "COMPLIANCE_STATUS should be set")
			assert.Equal(t, tt.expectedStatus, val.Str())
		})
	}
}

func TestApplier_NewApplier(t *testing.T) {
	logger := zap.NewNop()
	applier := NewApplier(logger)

	assert.NotNil(t, applier)
	assert.Equal(t, logger, applier.logger)
}

func TestApplier_ApplyWithEmptyArrays(t *testing.T) {
	applier := NewApplier(zap.NewNop())

	compliance := client.Compliance{
		Control: client.ComplianceControl{
			Id:        "TEST-1",
			CatalogId: "TEST-CATALOG",
			Category:  "Test Category",
		},
		Frameworks: client.ComplianceFrameworks{
			Requirements: []string{}, // Empty array
			Frameworks:   []string{}, // Empty array
		},
		EnrichmentStatus: client.Success,
	}

	logRecord := plog.NewLogRecord()
	attrs := logRecord.Attributes()

	err := applier.Apply(logRecord, compliance, "Passed")
	require.NoError(t, err)

	// Verify that empty arrays are handled correctly
	// The attributes should still be set but with empty slices
	reqVal, ok := attrs.Get(COMPLIANCE_REQUIREMENTS)
	if ok {
		assert.Equal(t, 0, reqVal.Slice().Len())
	}

	fwVal, ok := attrs.Get(COMPLIANCE_FRAMEWORKS)
	if ok {
		assert.Equal(t, 0, fwVal.Slice().Len())
	}
}

func stringPtr(s string) *string {
	return &s
}

func riskLevelPtr(level string) *client.ComplianceRiskLevel {
	riskLevel := client.ComplianceRiskLevel(level)
	return &riskLevel
}
