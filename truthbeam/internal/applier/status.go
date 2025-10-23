package applier

import "github.com/ossf/gemara/layer4"

type Status int

const (
	Compliant Status = iota
	NotCompliant
	NotApplicable
	Exempt
	Unknown
)

var toString = map[Status]string{
	Compliant:     "COMPLIANT",
	NotCompliant:  "NON_COMPLIANT",
	NotApplicable: "NOT_APPLICABLE",
	Exempt:        "EXEMPT",
	Unknown:       "UNKNOWN",
}

func (s Status) String() string {
	return toString[s]
}

func parseResult(resultStr string) layer4.Result {
	switch resultStr {
	case "Not Run":
		return layer4.NotRun
	case "Not Applicable":
		return layer4.NotApplicable
	case "Passed":
		return layer4.Passed
	case "Failed":
		return layer4.Failed
	default:
		return layer4.Unknown
	}
}

func mapResult(resultStr string) Status {
	result := parseResult(resultStr)
	switch result {
	case layer4.Passed:
		return Compliant
	case layer4.Failed:
		return NotCompliant
	case layer4.NotApplicable, layer4.NotRun:
		return NotApplicable
	default:
		return Unknown
	}
}
