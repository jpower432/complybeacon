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
	provider      log.LoggerProvider
	logger        log.Logger
	observer      *EvidenceObserver
	levelSeverity log.Severity
	opts          []log.LoggerOption
}

func NewProofWatch(name string, meter metric.Meter, options ...log.LoggerOption) (*ProofWatch, error) {
	provider := global.GetLoggerProvider()
	observer, err := NewEvidenceObserver(meter)
	if err != nil {
		return nil, err
	}
	return &ProofWatch{
		name:          name,
		provider:      provider,
		logger:        provider.Logger("proofwatch"),
		observer:      observer,
		levelSeverity: log.SeverityInfo,
		opts:          options,
	}, nil
}

func (w *ProofWatch) Log(ctx context.Context, event Evidence) error {
	attrs, err := w.logEvidence(ctx, event)
	if err != nil {
		return err
	}
	w.observer.Processed(ctx, attrs...)
	return nil
}

// LogEvidence logs the event to the global logger
func (w *ProofWatch) logEvidence(ctx context.Context, event Evidence) ([]attribute.KeyValue, error) {
	record := log.Record{}

	eventId, attrs := ToAttributes(event)
	record.SetEventName(eventId)
	record.SetObservedTimestamp(time.Now())

	var logAttrs []log.KeyValue
	for _, attr := range attrs {
		logAttrs = append(logAttrs, log.KeyValueFromAttribute(attr))
	}
	record.AddAttributes(logAttrs...)

	jsonData, err := json.Marshal(event)
	if err != nil {
		return attrs, err
	}
	evidenceLogData := log.StringValue(string(jsonData))
	record.SetBody(evidenceLogData)

	w.logger.Emit(ctx, record)
	return attrs, nil
}

func ToAttributes(event Evidence) (string, []attribute.KeyValue) {
	var defaultValue = "unknown"
	policySource := defaultValue
	policyName := defaultValue
	policyId := defaultValue
	policyAction := defaultValue
	policyDecision := defaultValue
	policyOutcome := defaultValue

	if event.Metadata.Product.Name != nil {
		policySource = *event.Metadata.Product.Name
	}

	if event.Policy.Uid != nil {
		policyId = *event.Policy.Uid
	}

	if event.Policy.Name != nil {
		policyName = *event.Policy.Uid
	}

	if event.ActionID != nil {
		policyAction = actionMap[*event.ActionID]
		if *event.ActionID != 3 && event.DispositionID != nil {
			policyOutcome = dispositionMap[*event.DispositionID]
		}
	}

	if event.Status != nil {
		policyDecision = *event.Status
	}

	attrs := []attribute.KeyValue{
		attribute.Int("category.id", int(event.CategoryUid)),
		attribute.Int("class.id", int(event.ClassUid)),
		attribute.String(POLICY_SOURCE, policySource),
		attribute.String(POLICY_ID, policyId),
		attribute.String(POLICY_NAME, policyName),
		attribute.String(POLICY_ENFORCEMENT_ACTION, policyAction),
		attribute.String(POLICY_EVALUATION_STATUS, policyDecision),
		attribute.String(POLICY_ENFORCEMENT_STATUS, policyOutcome),
	}

	return policyId, attrs
}

var actionMap = map[int32]string{
	0:  "Unknown",
	1:  "Allowed",
	2:  "Denied",
	3:  "Observed",
	4:  "Modified",
	99: "Other",
}

var dispositionMap = map[int32]string{
	0:  "Unknown",
	1:  "Allowed",
	2:  "Blocked",
	3:  "Quarantined",
	4:  "Isolated",
	5:  "Deleted",
	6:  "Dropped",
	7:  "Custom Action",
	8:  "Approved",
	9:  "Restored",
	10: "Exonerated",
	11: "Corrected",
	12: "Partially Corrected",
	13: "Uncorrected",
	14: "Delayed",
	15: "Detected",
	16: "No Action",
	17: "Logged",
	18: "Tagged",
	19: "Alert",
	20: "Count",
	21: "Reset",
	22: "Captcha",
	23: "Challenge",
	24: "Access Revoked",
	25: "Rejected",
	26: "Unauthorized",
	27: "Error",
	99: "Other",
}
