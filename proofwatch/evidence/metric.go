package evidence

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// EvidenceObserver handles observing and pushing compliance assessment metrics.
type EvidenceObserver struct {
	meter           *metric.Meter
	observableGauge metric.Float64ObservableGauge
	store           *Store
}

// NewEvidenceObserver creates a new EvidenceObserver and registers the callback.
func NewEvidenceObserver(meter metric.Meter, store *Store) (*EvidenceObserver, error) {
	co := &EvidenceObserver{
		meter: &meter,
		store: store,
	}

	var err error
	co.observableGauge, err = meter.Float64ObservableGauge(
		"evidence_status",
		metric.WithDescription("Current compliance assessment status (1=COMPLIANT, 0=NOT_COMPLIANT, -1=NOT_APPLICABLE)"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create observable gauge: %w", err)
	}

	_, err = meter.RegisterCallback(co.observeCallback, co.observableGauge)
	if err != nil {
		return nil, fmt.Errorf("failed to register callback: %w", err)
	}

	return co, nil
}

// observeCallback is the callback function for the observable gauge.
// It iterates through the evidence data store and observes the status.
func (co *EvidenceObserver) observeCallback(ctx context.Context, o metric.Observer) error {
	events := co.store.Events()
	for _, evidenceEvent := range events {
		rawEnv := evidenceEvent.Evidence

		statusValue := 0.0

		switch rawEnv.Decision {
		case "COMPLIANT":
			statusValue = 1.0
		case "NOT_COMPLIANT":
			statusValue = 0.0
		case "NOT_APPLICABLE":
			statusValue = -1.0
		default:
			statusValue = 0.0
		}

		attributes := metric.WithAttributes(
			attribute.String("policy.source", rawEnv.Source),
			attribute.String("resource.name", rawEnv.Subject.Name),
			attribute.String("evidenceEvent.id", rawEnv.ID),
			attribute.String("policy.decision", rawEnv.Decision),
			attribute.String("policy.id", rawEnv.PolicyID),
		)

		o.ObserveFloat64(co.observableGauge, statusValue, attributes)
	}
	return nil
}
