package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/complytime/complybeacon/proofwatch"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

// ApplyAttributes enriches attributes in the log record with compliance impact data.
func ApplyAttributes(ctx context.Context, client *Client, serverURL string, _ pcommon.Resource, logRecord plog.LogRecord) error {
	attrs := logRecord.Attributes()

	// Retrieve lookup attributes
	policyIDVal, ok := attrs.Get(proofwatch.POLICY_ID)
	if !ok {
		return fmt.Errorf("missing required attribute 'policy.id'")
	}

	policyAction, ok := attrs.Get(proofwatch.POLICY_ENFORCEMENT_ACTION)
	if !ok {
		return fmt.Errorf("missing required attribute 'policy.action'")
	}

	policySourceVal, ok := attrs.Get(proofwatch.POLICY_SOURCE)
	if !ok {
		return fmt.Errorf("missing required attribute 'policy.source'")
	}

	policyDecisionVal, ok := attrs.Get(proofwatch.POLICY_EVALUATION_STATUS)
	if !ok {
		return fmt.Errorf("missing required attributes 'policy.evaluation.status'")
	}
	enrichReq := EnrichmentRequest{
		Evidence: Evidence{
			Timestamp: logRecord.Timestamp().AsTime(),
			Source:    policySourceVal.Str(),
			PolicyId:  policyIDVal.Str(),
			Decision:  policyDecisionVal.Str(),
			Action:    policyAction.Str(),
		},
	}

	enrichRes, err := callEnrichAPI(ctx, client, serverURL, enrichReq)
	if err != nil {
		return err
	}

	attrs.PutStr(proofwatch.COMPLIANCE_STATUS, string(enrichRes.Status.Title))
	attrs.PutStr(proofwatch.COMPLIANCE_CONTROL_ID, enrichRes.Compliance.Control)
	attrs.PutStr(proofwatch.COMPLIANCE_CONTROL_CATALOG_ID, enrichRes.Compliance.Catalog)
	attrs.PutStr(proofwatch.COMPLIANCE_CATEGORY, enrichRes.Compliance.Category)
	requirements := attrs.PutEmptySlice(proofwatch.COMPLIANCE_REQUIREMENTS)
	standards := attrs.PutEmptySlice(proofwatch.COMPLIANCE_STANDARDS)

	if enrichRes.Compliance.Remediation != nil {
		attrs.PutStr("remediation.desc", *enrichRes.Compliance.Remediation)
	}

	for _, req := range enrichRes.Compliance.Requirements {
		newReq := requirements.AppendEmpty()
		newReq.SetStr(req)
	}
	for _, std := range enrichRes.Compliance.Standards {
		newStd := standards.AppendEmpty()
		newStd.SetStr(std)
	}

	return nil
}

// callEnrichAPI is a helper function to perform the actual HTTP request.
func callEnrichAPI(ctx context.Context, client *Client, serverURL string, req EnrichmentRequest) (*EnrichmentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// Create the HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", serverURL+"/v1/enrich", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Perform the request
	resp, err := client.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle non-200 status codes
	if resp.StatusCode != http.StatusOK {
		var errRes Error
		err := json.NewDecoder(resp.Body).Decode(&errRes)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("API call failed with status %d: %v", resp.StatusCode, errRes.Message)
	}

	// Decode the successful response
	var enrichRes EnrichmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrichRes); err != nil {
		return nil, err
	}

	return &enrichRes, nil
}
