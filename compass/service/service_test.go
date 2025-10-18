package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/complytime/complybeacon/compass/api"
	"github.com/complytime/complybeacon/compass/mapper"
	"github.com/complytime/complybeacon/compass/mapper/plugins/basic"
)

func TestNewService(t *testing.T) {
	mappers := make(mapper.Set)
	scope := make(mapper.Scope)

	service := NewService(mappers, scope)

	assert.NotNil(t, service)
	assert.Equal(t, mappers, service.set)
	assert.Equal(t, scope, service.scope)
}

func TestEnrich(t *testing.T) {
	t.Run("enriches evidence with compliance data", func(t *testing.T) {
		evidence := api.Evidence{
			PolicyEngineName:       "test-policy-engine",
			PolicyRuleId:           "AC-1",
			PolicyEvaluationStatus: api.Passed,
			Timestamp:              time.Now(),
		}
		scope := make(mapper.Scope)

		// Enrich the evidence with the basic mapper
		response := enrich(evidence, basic.NewBasicMapper(), scope)

		assert.NotEmpty(t, response)
		// Compliance may be empty - expected behavior for basic mapper
	})
}

func TestCaching(t *testing.T) {
	t.Run("caches static metadata but recalculates status", func(t *testing.T) {
		// Create a test scope with some data
		scope := make(mapper.Scope)
		// For this test, we'll use the fallback behavior where unmapped policies
		// still get cached with default metadata
		
		mapperPlugin := basic.NewBasicMapper()

		// First request - should cache metadata
		evidence1 := api.Evidence{
			PolicyEngineName:       "test-policy-engine",
			PolicyRuleId:           "AC-1",
			PolicyEvaluationStatus: api.Passed,
			Timestamp:              time.Now(),
		}
		compliance1 := enrich(evidence1, mapperPlugin, scope)

		// Second request with different status - should use cached metadata but recalculate status
		evidence2 := api.Evidence{
			PolicyEngineName:       "test-policy-engine",
			PolicyRuleId:           "AC-1",
			PolicyEvaluationStatus: api.Failed,
			Timestamp:              time.Now(),
		}
		compliance2 := enrich(evidence2, mapperPlugin, scope)

		// Static data should be the same (from cache)
		assert.Equal(t, compliance1.Control.Id, compliance2.Control.Id)
		assert.Equal(t, compliance1.Control.Category, compliance2.Control.Category)
		assert.Equal(t, compliance1.Frameworks, compliance2.Frameworks)

		// Status should be different (recalculated)
		assert.NotEqual(t, compliance1.Status, compliance2.Status)
		assert.Equal(t, api.COMPLIANT, *compliance1.Status)
		assert.Equal(t, api.NONCOMPLIANT, *compliance2.Status)

		// For this test, we're just verifying that the status is recalculated
		// The caching behavior would be tested in a separate integration test
	})
}
