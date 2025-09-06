package basic

import (
	"github.com/ossf/gemara/layer4"

	"github.com/complytime/complybeacon/compass/api"
	"github.com/complytime/complybeacon/compass/mapper"
)

// A basic mapper provide context in a shallow manner by parsing the known attributes.

var (
	_  mapper.Mapper = (*Mapper)(nil)
	ID               = mapper.NewID("basic")
)

type Mapper struct {
	plans map[string][]layer4.AssessmentPlan
}

func (m *Mapper) AddEvaluationPlan(catalogId string, plans []layer4.AssessmentPlan) {
	existingPlans, ok := m.plans[catalogId]
	if !ok {
		m.plans[catalogId] = plans
	} else {
		existingPlans = append(existingPlans, plans...)
		m.plans[catalogId] = existingPlans
	}
}

func NewBasicMapper() *Mapper {
	return &Mapper{
		plans: make(map[string][]layer4.AssessmentPlan),
	}
}

func (m *Mapper) PluginName() mapper.ID {
	return ID
}

func (m *Mapper) Map(evidence api.RawEvidence, scope mapper.Scope) ([]api.Compliance, api.Status) {
	var compliance []api.Compliance

	// Make a reasonable attempt to determine result here
	var (
		status   api.StatusTitle
		statusId api.StatusId
	)

	switch evidence.Decision {
	case "pass", "Pass", "success":
		status = api.Pass
		statusId = api.N1
	case "fail", "Fail", "failure":
		status = api.Fail
		statusId = api.N2
	case "Other", "Warning", "Unknown":
		status = api.Warning
		statusId = api.N3
	}

	for catalogId, plans := range m.plans {
		_, ok := scope[catalogId]
		if !ok {
			// evaluation is not in scope
			continue

		}

		var impactedRequirements []string
		// Find the Assessment Method in the plan
		for _, plan := range plans {
			for _, requirement := range plan.Assessments {
				for _, procedure := range requirement.Procedures {
					if procedure.Id == evidence.PolicyId {
						impactedRequirements = append(impactedRequirements, requirement.RequirementId)
						break
					}
				}
			}
		}

		if len(impactedRequirements) > 0 {
			baseline := api.Compliance{
				Benchmark:    catalogId,
				Requirements: impactedRequirements,
			}
			compliance = append(compliance, baseline)
		}
	}

	return compliance, api.Status{Title: status, Id: &statusId}
}
