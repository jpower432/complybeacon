package basic

import (
	"log"

	"github.com/ossf/gemara/layer2"
	"github.com/ossf/gemara/layer4"

	"github.com/complytime/complybeacon/compass/api"
	"github.com/complytime/complybeacon/compass/mapper"
)

// ProcedureInfo represents information about a procedure including its control and requirement IDs
type ProcedureInfo struct {
	ControlID     string
	RequirementID string
	Documentation string
}

// ControlData represents control information including mappings and category
type ControlData struct {
	Mappings []layer2.Mapping
	Category string
}

// A basic mapper processes assessment plans and maps evidence to compliance controls,
// requirements, and standards using the gemara framework.

var (
	_  mapper.Mapper = (*Mapper)(nil)
	ID               = mapper.NewID("basic")
)

type Mapper struct {
	plans map[string][]layer4.AssessmentPlan
}

func (m *Mapper) AddEvaluationPlan(catalogId string, plans ...layer4.AssessmentPlan) {
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

// GetMetadata returns static compliance metadata for a policy rule (can be cached)
func (m *Mapper) GetMetadata(policyRuleId string, scope mapper.Scope) (*api.ComplianceMetadata, api.ComplianceMetadataEnrichmentStatus) {
	// Track enrichment status
	enrichmentStatus := api.ComplianceMetadataEnrichmentStatusUnmapped
	var failureReasons []string

	// Process each catalog
	for catalogId, plans := range m.plans {
		catalog, ok := scope[catalogId]
		if !ok {
			log.Printf("WARNING: Catalog %s not found in scope for policy %s", catalogId, policyRuleId)
			failureReasons = append(failureReasons, "catalog not found")
			continue
		}

		// Build procedures map
		proceduresById := m.buildProceduresMap(plans)

		// Build control data map
		controlData := m.buildControlDataMap(catalog)

		// Look up policy in procedures
		if procedureInfo, ok := proceduresById[policyRuleId]; ok {

			// Look up control data
			if ctrlData, ok := controlData[procedureInfo.ControlID]; ok {
				metadata := &api.ComplianceMetadata{
					Control: api.ComplianceControl{
						Id:                     procedureInfo.RequirementID,
						Category:               ctrlData.Category,
						RemediationDescription: &procedureInfo.Documentation,
						CatalogId:              catalogId,
					},
					Frameworks: api.ComplianceFrameworks{
						Requirements: m.extractRequirements(ctrlData.Mappings),
						Frameworks:   m.extractStandards(ctrlData.Mappings),
					},
				}

				return metadata, api.ComplianceMetadataEnrichmentStatusSuccess
			} else {
				log.Printf("WARNING: Control data not found for control ID %s in catalog %s for policy %s", procedureInfo.ControlID, catalogId, policyRuleId)
				failureReasons = append(failureReasons, "control data not found")
			}
		} else {
			log.Printf("WARNING: Policy rule %s not found in procedures for catalog %s", policyRuleId, catalogId)
			failureReasons = append(failureReasons, "policy rule not found")
		}
	}

	// Log final failure if no mapping was found
	if len(failureReasons) > 0 {
		log.Printf("WARNING: Failed to map policy %s. Reasons: %v", policyRuleId, failureReasons)
	}

	// Return fallback metadata
	return &api.ComplianceMetadata{
		Control: api.ComplianceControl{
			Id:        policyRuleId,
			Category:  "Unknown",
			CatalogId: "unknown",
		},
		Frameworks: api.ComplianceFrameworks{
			Requirements: []string{},
			Frameworks:   []string{},
		},
	}, enrichmentStatus
}

// CalculateStatus calculates the dynamic status based on current evidence
func (m *Mapper) CalculateStatus(evidence api.Evidence) *api.ComplianceStatus {
	status := m.mapDecision(evidence.PolicyEvaluationStatus)
	return &status
}

// mapDecision maps a decision string to status and status ID.
func (m *Mapper) mapDecision(status api.EvidencePolicyEvaluationStatus) api.ComplianceStatus {
	switch status {
	case api.Passed:
		return api.COMPLIANT
	case api.Failed:
		return api.NONCOMPLIANT
	case api.NotRun, api.NotApplicable:
		return api.NOTAPPLICABLE
	default:
		return api.UNKNOWN
	}
}

// buildProceduresMap builds a map of procedure ID to procedure info.
func (m *Mapper) buildProceduresMap(plans []layer4.AssessmentPlan) map[string]ProcedureInfo {
	proceduresById := make(map[string]ProcedureInfo)

	for _, plan := range plans {
		for _, requirement := range plan.Assessments {
			for _, procedure := range requirement.Procedures {
				proceduresById[procedure.Id] = ProcedureInfo{
					ControlID:     plan.Control.EntryId,
					RequirementID: requirement.Requirement.EntryId,
					Documentation: procedure.Documentation,
				}
			}
		}
	}

	return proceduresById
}

// buildControlDataMap builds a map of control ID to control data.
func (m *Mapper) buildControlDataMap(catalog layer2.Catalog) map[string]ControlData {
	controlData := make(map[string]ControlData)

	for _, family := range catalog.ControlFamilies {
		for _, control := range family.Controls {
			controlData[control.Id] = ControlData{
				Mappings: control.GuidelineMappings,
				Category: family.Title,
			}
		}
	}

	return controlData
}

// extractRequirements extracts requirement IDs from mappings.
func (m *Mapper) extractRequirements(mappings []layer2.Mapping) []string {
	var requirements []string
	for _, mapping := range mappings {
		for _, entry := range mapping.Entries {
			requirements = append(requirements, entry.ReferenceId)
		}
	}
	return requirements
}

// extractStandards extracts standard IDs from mappings.
func (m *Mapper) extractStandards(mappings []layer2.Mapping) []string {
	var standards []string
	for _, mapping := range mappings {
		standards = append(standards, mapping.ReferenceId)
	}
	return standards
}
