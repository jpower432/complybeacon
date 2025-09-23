package proofwatch

import (
	"context"
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
)

type ProofWatch struct {
	name          string
	logger        log.Logger
	observer      *EvidenceObserver
	levelSeverity log.Severity
}

// NewProofWatch creates a new ProofWatch instance with OpenTelemetry logging.
func NewProofWatch(name string, meter metric.Meter) (*ProofWatch, error) {
	observer, err := NewEvidenceObserver(meter)
	if err != nil {
		return nil, err
	}
	return &ProofWatch{
		name:     name,
		logger:   global.GetLoggerProvider().Logger("proofwatch"),
		observer: observer,
	}, nil
}

// Log logs a policy event using OpenTelemetry's log API.
func (w *ProofWatch) Log(ctx context.Context, evidence Evidence) error {
	attrs := MapOCSFToAttributes(evidence)

	jsonData, err := json.Marshal(evidence)
	if err != nil {
		return err
	}

	record := log.Record{}
	record.SetEventName("gemara.policy.evaluation")
	record.SetObservedTimestamp(time.Now())
	record.AddAttributes(ToLogKeyValues(attrs)...)
	record.SetSeverity(w.levelSeverity)
	record.SetBody(log.StringValue(string(jsonData))) // Retains the original body for flexibility.

	w.logger.Emit(ctx, record)

	w.observer.Processed(ctx, attrs...)

	return nil
}

// MapOCSFToAttributes translates OCSF-based Evidence to Gemara-based attributes.
func MapOCSFToAttributes(event Evidence) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		// OCSF Standard Attributes (for interoperability)
		attribute.Int("category_uid", int(event.CategoryUid)),
		attribute.Int("class_uid", int(event.ClassUid)),

		attribute.String(POLICY_ID, stringVal(event.Policy.Uid, "unknown_policy_id")),
		attribute.String(POLICY_NAME, stringVal(event.Policy.Name, "unknown_policy_name")),
		attribute.String(POLICY_SOURCE, stringVal(event.Metadata.Product.Name, "unknown_source")),

		attribute.String(POLICY_EVALUATION_STATUS, mapEvaluationStatus(event.Status)),
		attribute.String(POLICY_STATUS_DETAIL, stringVal(event.Message, "")),

		attribute.String(POLICY_ENFORCEMENT_ACTION, mapEnforcementAction(event.ActionID, event.DispositionID)),
		attribute.String(POLICY_ENFORCEMENT_STATUS, mapEnforcementStatus(event.ActionID, event.DispositionID)),
	}

	return attrs
}

// ToLogKeyValues converts slice of attribute.KeyValue to log.KeyValue
func ToLogKeyValues(attrs []attribute.KeyValue) []log.KeyValue {
	logAttrs := make([]log.KeyValue, len(attrs))
	for i, attr := range attrs {
		logAttrs[i] = log.KeyValueFromAttribute(attr)
	}
	return logAttrs
}

// stringVal safely dereferences a string pointer with a default value.
func stringVal(s *string, defaultValue string) string {
	if s != nil {
		return *s
	}
	return defaultValue
}

// mapEvaluationStatus provides the core GRC logic for a pass/fail/error status.
// This is custom logic based on the policy engine's output.
func mapEvaluationStatus(status *string) string {
	if status == nil {
		return "error"
	}
	switch *status {
	case "success":
		return "pass"
	case "failure":
		return "fail"
	default:
		return "unknown"
	}
}

// mapEnforcementAction provides the core GRC logic for block/mutate/audit.
func mapEnforcementAction(actionID *int32, dispositionID *int32) string {
	if actionID == nil {
		return "audit" // Default to audit if no action is specified
	}
	switch *actionID {
	case 2: // Denied (OCSF) -> Block
		return "block"
	case 4: // Modified (OCSF) -> Mutate
		return "mutate"
	case 3, 16, 17: // Observed, No Action, Logged (OCSF) -> Audit
		return "audit"
	default:
		return "unknown"
	}
}

// mapEnforcementStatus maps OCSF dispositions to a simple success/fail for GRC.
func mapEnforcementStatus(actionID *int32, dispositionID *int32) string {
	if actionID == nil {
		return "success" // Audit/no action is a successful state
	}
	if *actionID == 2 && dispositionID != nil && (*dispositionID == 2 || *dispositionID == 6) { // Blocked, Dropped
		return "success" // A successful block
	}
	if *actionID == 4 && dispositionID != nil && *dispositionID == 11 { // Corrected
		return "success"
	}
	// Default to a fail or unknown for other cases
	return "fail"
}
