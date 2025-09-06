package evidence

import ocsf "github.com/Santiago-Labs/go-ocsf/ocsf/v1_5_0"

// TODO: Look into how to and when to apply the security controls profile. The application of that specific
// profile should be done by the `compass` service with data from `gemara` authored catalogs and profiles to perform correlation to
// controls and mapped threat data.

// OCSF-based evidence structured, with some security control profile fields

type Evidence struct {
	ocsf.ScanActivity `json:",inline"`
	// From the security-control profile
	Policy   ocsf.Policy `json:"policy" parquet:"policy"`
	Action   *string     `json:"action,omitempty" parquet:"action,optional"`
	ActionID *int32      `json:"action_id,omitempty" parquet:"action_id,optional"`
}
