package mapper

import (
	"testing"

	"github.com/ossf/gemara/layer2"
	"github.com/ossf/gemara/layer4"
	"github.com/stretchr/testify/assert"

	"github.com/complytime/complybeacon/compass/api"
)

// mockMapper is a test implementation of the Mapper interface
type mockMapper struct {
	id    ID
	plans map[string][]layer4.AssessmentPlan
}

func (m *mockMapper) PluginName() ID {
	return m.id
}

func (m *mockMapper) GetMetadata(policyRuleId string, scope Scope) (*api.ComplianceMetadata, api.ComplianceMetadataEnrichmentStatus) {
	return &api.ComplianceMetadata{
		Control: api.ComplianceControl{
			Id:        policyRuleId,
			Category:  "test-category",
			CatalogId: "test-catalog",
		},
		Frameworks: api.ComplianceFrameworks{
			Requirements: []string{"req-1"},
			Frameworks:   []string{"NIST-800-53"},
		},
	}, api.ComplianceMetadataEnrichmentStatusSuccess
}

func (m *mockMapper) CalculateStatus(evidence api.Evidence) *api.ComplianceStatus {
	return statusPtr(api.COMPLIANT)
}

func (m *mockMapper) AddEvaluationPlan(catalogId string, plans ...layer4.AssessmentPlan) {
	if m.plans == nil {
		m.plans = make(map[string][]layer4.AssessmentPlan)
	}
	m.plans[catalogId] = plans
}

func TestNewID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ID
	}{
		{
			name:     "basic string",
			input:    "test-mapper",
			expected: ID("test-mapper"),
		},
		{
			name:     "empty string",
			input:    "",
			expected: ID(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSet tests map operations (add, retrieve, delete) on the Set type
func TestSet(t *testing.T) {
	set := make(Set)

	policyMapper := &mockMapper{id: "policy-mapper"}
	controlMapper := &mockMapper{id: "control-mapper"}

	// Add mappers
	set[ID("policy-mapper")] = policyMapper
	set[ID("control-mapper")] = controlMapper

	assert.Len(t, set, 2)
	assert.Contains(t, set, ID("policy-mapper"))
	assert.Contains(t, set, ID("control-mapper"))
	assert.Equal(t, policyMapper, set[ID("policy-mapper")])
	assert.Equal(t, controlMapper, set[ID("control-mapper")])

	// Retrieve existing mapper
	retrieved, exists := set[ID("policy-mapper")]
	assert.True(t, exists)
	assert.Equal(t, policyMapper, retrieved)

	// Retrieve non-existent mapper
	_, exists = set[ID("non-existent")]
	assert.False(t, exists)

	// Delete mapper
	delete(set, ID("policy-mapper"))
	assert.Len(t, set, 1)
	assert.NotContains(t, set, ID("policy-mapper"))
	assert.Contains(t, set, ID("control-mapper"))
}

func TestScope(t *testing.T) {
	scope := make(Scope)

	catalog1 := layer2.Catalog{Metadata: layer2.Metadata{Id: "catalog-1"}}
	catalog2 := layer2.Catalog{Metadata: layer2.Metadata{Id: "catalog-2"}}

	// Add catalogs
	scope["catalog-1"] = catalog1
	scope["catalog-2"] = catalog2

	assert.Len(t, scope, 2)
	assert.Contains(t, scope, "catalog-1")
	assert.Contains(t, scope, "catalog-2")
	assert.Equal(t, catalog1, scope["catalog-1"])
	assert.Equal(t, catalog2, scope["catalog-2"])

	// Retrieve existing catalog
	retrieved, exists := scope["catalog-1"]
	assert.True(t, exists)
	assert.Equal(t, catalog1, retrieved)

	// Retrieve non-existent catalog
	_, exists = scope["non-existent"]
	assert.False(t, exists)
}

// TestMapperInterfaceAndIDType tests ID type operations and mock mapper interface implementation
func TestMapperInterfaceAndIDType(t *testing.T) {
	t.Run("ID type operations", func(t *testing.T) {
		id1 := ID("test-id")
		id2 := ID("test-id")
		id3 := ID("different-id")

		assert.Equal(t, id1, id2)
		assert.NotEqual(t, id1, id3)

		assert.Equal(t, "test-id", string(id1))
		assert.Equal(t, "different-id", string(id3))
	})
}

func statusPtr(status api.ComplianceStatus) *api.ComplianceStatus {
	return &status
}
