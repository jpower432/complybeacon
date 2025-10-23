package proofwatch

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	ocsf "github.com/Santiago-Labs/go-ocsf/ocsf/v1_5_0"
	"go.opentelemetry.io/otel/attribute"
)

var _ Evidence = (*OCSFEvidence)(nil)

// OCSF-based evidence structured, with some security control profile fields. Attributes for `compliance` findings
// by the `compass` service based on `gemara` based during pipeline enrichment.

type OCSFEvidence struct {
	ocsf.ScanActivity `json:",inline"`
	// From the security-control profile
	Policy        ocsf.Policy `json:"policy" parquet:"policy"`
	Action        *string     `json:"action,omitempty" parquet:"action,optional"`
	ActionID      *int32      `json:"action_id,omitempty" parquet:"action_id,optional"`
	Disposition   *string     `json:"disposition,omitempty" parquet:"action,optional"`
	DispositionID *int32      `json:"disposition_id,omitempty" parquet:"action_id,optional"`
}

func (o OCSFEvidence) Timestamp() time.Time {
	return time.UnixMilli(o.Time)
}

func (o OCSFEvidence) ToJSON() ([]byte, error) {
	return json.Marshal(o)
}

func (o OCSFEvidence) Attributes() []attribute.KeyValue {
	// Validate critical fields - log warnings for missing data but continue processing
	// This allows the pipeline to continue even with incomplete data
	if err := validateEvidenceFields(o); err != nil {
		log.Printf("validation error %v, using default values", err)
	}

	attrs := []attribute.KeyValue{
		// OCSF Standard Attributes (for interoperability)
		attribute.Int("ocsf.category.uid", int(o.CategoryUid)),
		attribute.Int("ocsf.class.uid", int(o.ClassUid)),

		attribute.String(POLICY_RULE_ID, stringVal(o.Policy.Uid, "unknown_policy_id")),
		attribute.String(POLICY_RULE_NAME, stringVal(o.Policy.Name, "unknown_policy_name")),
		attribute.String(POLICY_ENGINE_NAME, stringVal(o.Metadata.Product.Name, "unknown_source")),

		attribute.String(POLICY_EVALUATION_RESULT, mapEvaluationStatus(o.Status)),
		attribute.String(POLICY_EVALUATION_MESSAGE, stringVal(o.Message, "")),

		attribute.String(COMPLIANCE_REMEDIATION_ACTION, mapEnforcementAction(o.ActionID, o.DispositionID)),
		attribute.String(COMPLIANCE_REMEDIATION_STATUS, mapEnforcementStatus(o.ActionID, o.DispositionID)),
	}

	return attrs
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
		return "Unknown"
	}
	switch *status {
	case "success":
		return "Passed"
	case "failure":
		return "Failed"
	default:
		return "Unknown"
	}
}

// mapEnforcementAction provides the core GRC logic for block/mutate/audit.
func mapEnforcementAction(actionID *int32, dispositionID *int32) string {
	if actionID == nil {
		return "Notify" // Default to Notify if no action is specified
	}
	switch *actionID {
	case 2: // Denied (OCSF) -> Block
		return "Block"
	case 4: // Modified (OCSF) -> Remediate
		return "Remediate"
	case 3, 16, 17: // Observed, No Action, Logged (OCSF) -> Notify
		return "Notify"
	default:
		return "Unknown"
	}
}

// mapEnforcementStatus maps OCSF dispositions to a simple success/fail for GRC.
func mapEnforcementStatus(actionID *int32, dispositionID *int32) string {
	if actionID == nil {
		return "Allow" // Notify/no action is a successful state
	}
	if *actionID == 2 && dispositionID != nil && (*dispositionID == 2 || *dispositionID == 6) { // Blocked, Dropped
		return "Block" // A successful block
	}
	if *actionID == 4 && dispositionID != nil && *dispositionID == 11 { // Corrected
		return "Remediate"
	}
	// Default to a fail or unknown for other cases
	return "Unknown"
}

// validateEvidenceFields performs basic validation on Evidence fields and logs warnings
// for missing critical data. This allows the pipeline to continue processing even with
// incomplete data, which is important for resilience.
func validateEvidenceFields(event OCSFEvidence) error {
	if event.Policy.Uid == nil || *event.Policy.Uid == "" {
		return errors.New("event is missing a policy id")
	}

	if event.Metadata.Product.Name == nil || *event.Metadata.Product.Name == "" {
		return errors.New("event is missing a policy source")
	}

	if event.Status == nil || *event.Status == "" {
		return errors.New("the event is missing a policy status")
	}
	return nil
}
