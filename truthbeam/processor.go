package truthbeam

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"

	"github.com/complytime/complybeacon/truthbeam/internal/applier"
	"github.com/complytime/complybeacon/truthbeam/internal/client"
)

type truthBeamProcessor struct {
	telemetry component.TelemetrySettings
	config    *Config

	logger *zap.Logger

	client  *client.CacheableClient
	applier *applier.Applier
}

func newTruthBeamProcessor(conf component.Config, set processor.Settings) (*truthBeamProcessor, error) {
	cfg, ok := conf.(*Config)
	if !ok {
		return nil, errors.New("invalid configuration provided")
	}

	return &truthBeamProcessor{
		config:    cfg,
		telemetry: set.TelemetrySettings,
		logger:    set.Logger,
		client:    nil,
		applier:   applier.NewApplier(set.Logger),
	}, nil
}

func (t *truthBeamProcessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	rl := ld.ResourceLogs()
	for i := 0; i < rl.Len(); i++ {
		rs := rl.At(i)
		ilss := rs.ScopeLogs()
		for j := 0; j < ilss.Len(); j++ {
			ils := ilss.At(j)
			logs := ils.LogRecords()
			for k := 0; k < logs.Len(); k++ {
				logRecord := logs.At(k)

				// Extract evidence from log record
				evidence, err := t.applier.ExtractEvidence(logRecord)
				if err != nil {
					t.logger.Debug("Failed to extract evidence from log record", zap.Error(err))
					continue
				}

				// Get enrichment data (with caching)
				enrichment, err := t.client.Retrieve(ctx, evidence)
				if err != nil {
					// We don't want to return an error here to ensure the evidence
					// is not dropped. It will just be unmapped.

					// TODO: Add enrichment status failed

					t.logger.Error("failed to get enrichment",
						zap.String("policy_id", evidence.PolicyRuleId),
						zap.Error(err))
					continue
				}

				// Apply enrichment to log record
				err = t.applier.ApplyEnrichment(ctx, logRecord, &enrichment)
				if err != nil {
					t.logger.Error("failed to apply enrichment",
						zap.String("policy_id", evidence.PolicyRuleId),
						zap.Error(err))
				}
			}
		}
	}
	return ld, nil
}

// start will add HTTP client and pre-fetch any policy data
func (t *truthBeamProcessor) start(ctx context.Context, host component.Host) error {
	httpClient, err := t.config.ClientConfig.ToClient(ctx, host, t.telemetry)
	if err != nil {
		return err
	}

	baseClient, err := client.NewClient(t.config.ClientConfig.Endpoint, client.WithHTTPClient(httpClient))
	if err != nil {
		return err
	}

	// Create enriched client with caching
	t.client = client.NewCacheableClient(baseClient, t.logger)

	// Pre-fetch any configured policy data
	if len(t.config.Prefetch) > 0 {
		t.logger.Info("Starting prefetch of policy data",
			zap.Strings("prefetch_urls", t.config.Prefetch))

		// Convert prefetch URLs to evidence for prefetching
		// This is a simplified approach - in practice, you might want to
		// fetch actual policy data and create evidence from it
		var evidenceList []client.Evidence
		for _, url := range t.config.Prefetch {
			// Create a sample evidence for prefetching
			// In a real implementation, you'd fetch the actual policy data
			evidenceList = append(evidenceList, client.Evidence{
				PolicyRuleId:           "prefetch-" + url,
				PolicyEngineName:       "prefetch",
				PolicyEvaluationStatus: client.Unknown,
				Timestamp:              time.Now(),
			})
		}

		if err := t.client.Prefetch(ctx, evidenceList); err != nil {
			t.logger.Warn("Failed to prefetch some policy data", zap.Error(err))
		}
	}

	return nil
}
