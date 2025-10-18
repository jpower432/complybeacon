package applier

import (
	"context"
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

// ApplyEnrichment applies enrichment data to a log record
func (a *Applier) ApplyEnrichment(ctx context.Context, logRecord plog.LogRecord, enrichment *client.EnrichmentResponse) error {
	if enrichment == nil {
		return fmt.Errorf("enrichment response is nil")
	}

	attrs := logRecord.Attributes()

	// Apply compliance status
	status := ""
	if enrichment.Compliance.Status != nil {
		status = string(*enrichment.Compliance.Status)
	}
	attrs.PutStr(client.COMPLIANCE_STATUS, status)
	attrs.PutStr(client.COMPLIANCE_CONTROL_ID, enrichment.Compliance.Control.Id)
	attrs.PutStr(client.COMPLIANCE_CONTROL_CATALOG_ID, enrichment.Compliance.Control.CatalogId)
	attrs.PutStr(client.COMPLIANCE_CONTROL_CATEGORY, enrichment.Compliance.Control.Category)

	// Apply requirements
	requirements := attrs.PutEmptySlice(client.COMPLIANCE_REQUIREMENTS)
	for _, req := range enrichment.Compliance.Frameworks.Requirements {
		newReq := requirements.AppendEmpty()
		newReq.SetStr(req)
	}

	standards := attrs.PutEmptySlice(client.COMPLIANCE_FRAMEWORKS)
	for _, std := range enrichment.Compliance.Frameworks.Frameworks {
		newStd := standards.AppendEmpty()
		newStd.SetStr(std)
	}

	// Apply remediation if available
	if enrichment.Compliance.Control.RemediationDescription != nil {
		attrs.PutStr(client.COMPLIANCE_REMEDIATION_DESCRIPTION, *enrichment.Compliance.Control.RemediationDescription)
	}

	a.logger.Debug("Applied enrichment to log record")

	return nil
}

// ExtractEvidence extracts evidence data from a log record for enrichment requests
func (a *Applier) ExtractEvidence(logRecord plog.LogRecord) (*client.Evidence, error) {
	attrs := logRecord.Attributes()

	// Retrieve lookup attributes
	policyRuleIDVal, ok := attrs.Get(client.POLICY_RULE_ID)
	if !ok {
		return nil, fmt.Errorf("missing required attribute %q", client.POLICY_RULE_ID)
	}

	policySourceVal, ok := attrs.Get(client.POLICY_ENGINE_NAME)
	if !ok {
		return nil, fmt.Errorf("missing required attribute %q", client.POLICY_ENGINE_NAME)
	}

	policyEvalStatusVal, ok := attrs.Get(client.POLICY_EVALUATION_RESULT)
	if !ok {
		return nil, fmt.Errorf("missing required attributes %q", client.POLICY_EVALUATION_RESULT)
	}

	evidence := &client.Evidence{
		Timestamp:              logRecord.Timestamp().AsTime(),
		PolicyEngineName:       policySourceVal.Str(),
		PolicyRuleId:           policyRuleIDVal.Str(),
		PolicyEvaluationStatus: client.EvidencePolicyEvaluationStatus(policyEvalStatusVal.Str()),
	}

	return evidence, nil
}
