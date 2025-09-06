package evidence

import (
	"context"
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
)

type InstrumentationFn func(ctx context.Context, event Evidence) error

func NewEmitter(observer *EvidenceObserver) InstrumentationFn {
	return func(ctx context.Context, event Evidence) error {
		attrs, err := LogEvidence(ctx, event)
		if err != nil {
			return err
		}
		observer.Processed(ctx, attrs...)
		return nil
	}
}

// LogEvidence logs the event to the global logger
func LogEvidence(ctx context.Context, event Evidence) ([]attribute.KeyValue, error) {
	logger := global.Logger("proofwatch")
	record := log.Record{}

	eventId, attrs := ToAttributes(event)
	record.SetEventName(eventId)
	timestamp := time.UnixMilli(event.Time)
	record.SetTimestamp(timestamp)
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
	findingData := log.BytesValue(jsonData)
	record.SetBody(findingData)

	logger.Emit(ctx, record)
	return attrs, nil
}

func ToAttributes(event Evidence) (string, []attribute.KeyValue) {
	var defaultValue = "unknown"
	policySource := defaultValue
	evidenceId := defaultValue
	policyDecision := defaultValue
	policyId := defaultValue

	if event.Metadata.Product.Name != nil {
		policySource = *event.Metadata.Product.Name
	}

	if event.Metadata.Uid != nil {
		evidenceId = *event.Metadata.Uid
	}

	if event.Policy.Uid != nil {
		policyId = *event.Policy.Uid
	}

	if event.Status != nil {
		policyDecision = *event.Status
	}

	return evidenceId, []attribute.KeyValue{
		attribute.Int("category.id", int(event.CategoryUid)),
		attribute.Int("class.id", int(event.ClassUid)),
		attribute.String("policy.source", policySource),
		attribute.String("policy.id", policyId),
		attribute.String("policy.decision", policyDecision),
		attribute.String("evidence.id", evidenceId),
	}
}
