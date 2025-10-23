package proofwatch

import (
	"testing"
	"time"

	ocsf "github.com/Santiago-Labs/go-ocsf/ocsf/v1_5_0"
	"github.com/stretchr/testify/assert"
)

func TestOCSFEvidenceAttributes(t *testing.T) {
	evidence := createTestEvidence()
	attrs := evidence.Attributes()

	// Check that required attributes are present
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	// Verify policy attributes
	assert.Equal(t, "test-policy", attrMap[POLICY_RULE_ID])
	assert.Equal(t, "test-policy", attrMap[POLICY_RULE_NAME])
	assert.Equal(t, "test-product", attrMap[POLICY_ENGINE_NAME])

	// Verify evaluation status mapping
	assert.Equal(t, "Passed", attrMap[POLICY_EVALUATION_RESULT])
}

func TestMapEvaluationStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   *string
		expected string
	}{
		{
			name:     "success status",
			status:   stringPtr("success"),
			expected: "Passed",
		},
		{
			name:     "failure status",
			status:   stringPtr("failure"),
			expected: "Failed",
		},
		{
			name:     "unknown status",
			status:   stringPtr("unknown"),
			expected: "Unknown",
		},
		{
			name:     "nil status",
			status:   nil,
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapEvaluationStatus(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapEnforcementAction(t *testing.T) {
	tests := []struct {
		name          string
		actionID      *int32
		dispositionID *int32
		expected      string
	}{
		{
			name:     "denied action",
			actionID: int32Ptr(2),
			expected: "Block",
		},
		{
			name:     "modified action",
			actionID: int32Ptr(4),
			expected: "Remediate",
		},
		{
			name:     "observed action",
			actionID: int32Ptr(3),
			expected: "Notify",
		},
		{
			name:     "no action",
			actionID: int32Ptr(16),
			expected: "Notify",
		},
		{
			name:     "logged action",
			actionID: int32Ptr(17),
			expected: "Notify",
		},
		{
			name:     "nil action",
			actionID: nil,
			expected: "Notify",
		},
		{
			name:     "unknown action",
			actionID: int32Ptr(99),
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapEnforcementAction(tt.actionID, tt.dispositionID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMapEnforcementStatus(t *testing.T) {
	tests := []struct {
		name          string
		actionID      *int32
		dispositionID *int32
		expected      string
	}{
		{
			name:     "nil action",
			actionID: nil,
			expected: "Allow",
		},
		{
			name:          "successful block",
			actionID:      int32Ptr(2),
			dispositionID: int32Ptr(2),
			expected:      "Block",
		},
		{
			name:          "successful correction",
			actionID:      int32Ptr(4),
			dispositionID: int32Ptr(11),
			expected:      "Remediate",
		},
		{
			name:          "failed enforcement",
			actionID:      int32Ptr(2),
			dispositionID: int32Ptr(1),
			expected:      "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapEnforcementStatus(tt.actionID, tt.dispositionID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateEvidenceFields(t *testing.T) {
	tests := []struct {
		name     string
		evidence OCSFEvidence
		wantErr  bool
	}{
		{
			name: "valid evidence",
			evidence: func() OCSFEvidence {
				policyName := "test-policy"
				productName := "test-product"
				status := "success"
				return OCSFEvidence{
					ScanActivity: ocsf.ScanActivity{
						Time: time.Now().UnixMilli(),
						Metadata: ocsf.Metadata{
							Product: ocsf.Product{
								Name: &productName,
							},
						},
						Status: &status,
					},
					Policy: ocsf.Policy{
						Uid:  &policyName,
						Name: &policyName,
					},
				}
			}(),
			wantErr: false,
		},
		{
			name: "missing policy id",
			evidence: func() OCSFEvidence {
				productName := "test-product"
				status := "success"
				return OCSFEvidence{
					Policy: ocsf.Policy{},
					ScanActivity: ocsf.ScanActivity{
						Time: time.Now().UnixMilli(),
						Metadata: ocsf.Metadata{
							Product: ocsf.Product{
								Name: &productName,
							},
						},
						Status: &status,
					},
				}
			}(),
			wantErr: true,
		},
		{
			name: "missing product name",
			evidence: func() OCSFEvidence {
				policyName := "test-policy"
				status := "success"
				return OCSFEvidence{
					ScanActivity: ocsf.ScanActivity{
						Time:     time.Now().UnixMilli(),
						Metadata: ocsf.Metadata{},
						Status:   &status,
					},
					Policy: ocsf.Policy{
						Uid:  &policyName,
						Name: &policyName,
					},
				}
			}(),
			wantErr: true,
		},
		{
			name: "missing status",
			evidence: func() OCSFEvidence {
				policyName := "test-policy"
				productName := "test-product"
				return OCSFEvidence{
					ScanActivity: ocsf.ScanActivity{
						Time: time.Now().UnixMilli(),
						Metadata: ocsf.Metadata{
							Product: ocsf.Product{
								Name: &productName,
							},
						},
					},
					Policy: ocsf.Policy{
						Uid:  &policyName,
						Name: &policyName,
					},
				}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEvidenceFields(tt.evidence)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to create test evidence
func createTestEvidence() OCSFEvidence {
	policyName := "test-policy"
	productName := "test-product"
	status := "success"

	return OCSFEvidence{
		ScanActivity: ocsf.ScanActivity{
			Time: time.Now().UnixMilli(),
			Metadata: ocsf.Metadata{
				Product: ocsf.Product{
					Name: &productName,
				},
			},
			Status: &status,
		},
		Policy: ocsf.Policy{
			Uid:  &policyName,
			Name: &policyName,
		},
	}
}

func TestOCSFEvidenceTargetAttributes(t *testing.T) {
	scanUid := "scan-123"
	scanType := "vulnerability"
	policyName := "test-policy"
	productName := "test-product"
	status := "success"

	evidence := OCSFEvidence{
		ScanActivity: ocsf.ScanActivity{
			Time: time.Now().UnixMilli(),
			Metadata: ocsf.Metadata{
				Product: ocsf.Product{
					Name: &productName,
				},
			},
			Status: &status,
			Scan: ocsf.Scan{
				Uid:  &scanUid,
				Type: &scanType,
			},
		},
		Policy: ocsf.Policy{
			Uid:  &policyName,
			Name: &policyName,
		},
	}

	attrs := evidence.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	// Verify target attributes are present
	assert.Equal(t, scanUid, attrMap[POLICY_TARGET_ID])
	assert.Equal(t, scanType, attrMap[POLICY_TARGET_TYPE])
}
