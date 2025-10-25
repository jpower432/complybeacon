package applier

import (
	"fmt"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/complytime/complybeacon/truthbeam/internal/client"
)

// Applier handles the application of enrichment data to log records
type Applier struct {
	logger *zap.Logger
}

// NewApplier creates a new Applier instance
func NewApplier(logger *zap.Logger) *Applier {
	return &Applier{
		logger: logger,
	}
}

// Apply applies compliance data to a log record
func (a *Applier) Apply(logRecord plog.LogRecord, compliance client.Compliance, result string) error {
	attrs := logRecord.Attributes()

	// Map the evaluation result to a compliance status
	status := mapResult(result)
	attrs.PutStr(COMPLIANCE_STATUS, status.String())

	attrs.PutStr(COMPLIANCE_ENRICHMENT_STATUS, string(compliance.EnrichmentStatus))
	if compliance.EnrichmentStatus == client.Unmapped {
		return nil
	}

	// Continue adding attributes if the enrichment was successful
	attrs.PutStr(COMPLIANCE_CONTROL_ID, compliance.Control.Id)
	attrs.PutStr(COMPLIANCE_CONTROL_CATALOG_ID, compliance.Control.CatalogId)
	attrs.PutStr(COMPLIANCE_CONTROL_CATEGORY, compliance.Control.Category)

	// Apply requirements
	requirements := attrs.PutEmptySlice(COMPLIANCE_REQUIREMENTS)
	for _, req := range compliance.Frameworks.Requirements {
		newReq := requirements.AppendEmpty()
		newReq.SetStr(req)
	}

	standards := attrs.PutEmptySlice(COMPLIANCE_FRAMEWORKS)
	for _, std := range compliance.Frameworks.Frameworks {
		newStd := standards.AppendEmpty()
		newStd.SetStr(std)
	}

	// Apply remediation if available
	if compliance.Control.RemediationDescription != nil {
		attrs.PutStr(COMPLIANCE_REMEDIATION_DESCRIPTION, *compliance.Control.RemediationDescription)
	}

	if compliance.Risk != nil && compliance.Risk.Level != nil {
		attrs.PutStr(COMPLIANCE_RISK_LEVEL, string(*compliance.Risk.Level))
	}

	return nil
}

// Extract extracts policy data from a log record for requests
func (a *Applier) Extract(logRecord plog.LogRecord) (client.Policy, string, error) {
	attrs := logRecord.Attributes()

	// Retrieve lookup attributes
	policyRuleIDVal, ok := attrs.Get(POLICY_RULE_ID)
	if !ok {
		return client.Policy{}, "", fmt.Errorf("missing required attribute %q", POLICY_RULE_ID)
	}

	policySourceVal, ok := attrs.Get(POLICY_ENGINE_NAME)
	if !ok {
		return client.Policy{}, "", fmt.Errorf("missing required attribute %q", POLICY_ENGINE_NAME)
	}

	policyEvalStatusVal, ok := attrs.Get(POLICY_EVALUATION_RESULT)
	if !ok {
		return client.Policy{}, "", fmt.Errorf("missing required attributes %q", POLICY_EVALUATION_RESULT)
	}

	policy := client.Policy{
		PolicyEngineName: policySourceVal.Str(),
		PolicyRuleId:     policyRuleIDVal.Str(),
	}

	return policy, policyEvalStatusVal.AsString(), nil
}
