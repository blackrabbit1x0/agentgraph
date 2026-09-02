package aws

import (
	"encoding/json"
	"strings"
)

// trustPolicy is the subset of an IAM policy document needed to extract
// assume-role trust relationships.
type trustPolicy struct {
	Statement []trustStatement `json:"Statement"`
}

type trustStatement struct {
	Effect    string          `json:"Effect"`
	Principal trustPrincipal  `json:"Principal"`
	Action    json.RawMessage `json:"Action"`
}

type trustPrincipal struct {
	AWS json.RawMessage `json:"AWS"`
}

// ParseTrustPrincipals extracts the AWS principal ARNs allowed to assume
// a role, from its trust policy JSON. Wildcards, account-root ARNs, and
// service principals are normalized:
//
//	"*"                          -> "arn:aws:iam::*:root" (dangerous wildcard)
//	"arn:aws:iam::123:root"      -> kept (account root = any principal in account)
//	"arn:aws:sts::123:assumed-role/..." -> collapsed to the owning role ARN
func ParseTrustPrincipals(policyJSON string) []string {
	if policyJSON == "" {
		return nil
	}
	var doc trustPolicy
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if !actionAssumesRole(st.Action) {
			continue
		}
		for _, p := range parseAWSPrincipals(st.Principal.AWS) {
			if p == "*" {
				p = "arn:aws:iam::*:root"
			}
			p = collapseAssumedRole(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func actionAssumesRole(raw json.RawMessage) bool {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return strings.Contains(single, "sts:AssumeRole")
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		for _, a := range many {
			if strings.Contains(a, "sts:AssumeRole") {
				return true
			}
		}
	}
	return false
}

func parseAWSPrincipals(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// collapseAssumedRole converts an assumed-role session ARN to the role ARN
// that owns it:
//
//	arn:aws:sts::123:assumed-role/MyRole/session-name
//	  -> arn:aws:iam::123:role/MyRole
func collapseAssumedRole(arn string) string {
	// arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION
	segments := strings.SplitN(arn, ":assumed-role/", 2)
	if len(segments) != 2 {
		return arn
	}
	fields := strings.Split(segments[0], ":")
	if len(fields) < 5 {
		return arn
	}
	account := fields[4]
	role := strings.SplitN(segments[1], "/", 2)
	if len(role) != 2 {
		return arn
	}
	return "arn:aws:iam::" + account + ":role/" + role[0]
}
