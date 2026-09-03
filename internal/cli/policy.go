package cli

import (
	"fmt"
	"os"

	"github.com/blackrabbit1x0/agentgraph/internal/paths"
	"github.com/blackrabbit1x0/agentgraph/internal/policy"
	"github.com/blackrabbit1x0/agentgraph/internal/risk"
	"github.com/spf13/cobra"
)

func newPolicyCommand() *cobra.Command {
	var policyFile string

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate policy rules against the graph",
		Long: `Evaluate policy rules against the graph.

Without --rules, the embedded default rule set is used:
  AGENT-001  agents must not reach administrative access   (critical)
  AGENT-002  agents must not reach production environments (critical)
  AGENT-003  agents must not reach secrets                 (high)

Custom YAML rule sets follow this format:

  rules:
    - id: AGENT-100
      name: Agents must not reach payment infrastructure
      severity: critical
      when:
        node_type: AI_AGENT
      deny_reach:
        has_any_tag: [payments, billing]
        environment: production`,
		Run: func(cmd *cobra.Command, args []string) {
			g, _ := loadGraph()

			var set *policy.Set
			if policyFile != "" {
				data, err := os.ReadFile(policyFile)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					return
				}
				set, err = policy.Parse(data)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					return
				}
			} else {
				set = policy.DefaultRules()
			}

			violations, err := policy.Evaluate(g, set, paths.Options{})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				return
			}
			printViolations(violations, policyFile)
		},
	}
	cmd.Flags().StringVar(&policyFile, "rules", "", "path to a custom rules YAML file (default: embedded rules)")
	return cmd
}

func printViolations(violations []*policy.Violation, policyFile string) {
	if policyFile == "" {
		fmt.Println("POLICY REPORT (default rules)")
	} else {
		fmt.Printf("POLICY REPORT (%s)\n", policyFile)
	}
	fmt.Println()

	if len(violations) == 0 {
		fmt.Println("No violations. All rules pass.")
		return
	}

	// Group by rule.
	type ruleGroup struct {
		id, name, severity string
		vs                 []*policy.Violation
	}
	groups := []*ruleGroup{}
	index := map[string]*ruleGroup{}
	for _, v := range violations {
		grp, ok := index[v.RuleID]
		if !ok {
			grp = &ruleGroup{id: v.RuleID, name: v.RuleName, severity: v.Severity}
			index[v.RuleID] = grp
			groups = append(groups, grp)
		}
		grp.vs = append(grp.vs, v)
	}

	sevRank := map[string]int{
		risk.SeverityCritical: 4, risk.SeverityHigh: 3,
		risk.SeverityMedium: 2, risk.SeverityLow: 1,
	}
	// Sort groups by severity then id.
	for i := 0; i < len(groups); i++ {
		for j := i + 1; j < len(groups); j++ {
			gi, gj := groups[i], groups[j]
			if sevRank[gi.severity] < sevRank[gj.severity] ||
				(sevRank[gi.severity] == sevRank[gj.severity] && gi.id > gj.id) {
				groups[i], groups[j] = groups[j], groups[i]
			}
		}
	}

	total := len(violations)
	critical := 0
	for _, v := range violations {
		if v.Severity == risk.SeverityCritical {
			critical++
		}
	}
	fmt.Printf("Violations: %d (%d critical)\n\n", total, critical)

	for _, grp := range groups {
		fmt.Printf("[%s] %s (%s)\n", grp.severity, grp.id, grp.name)
		for _, v := range grp.vs {
			fmt.Printf("  %s -> %s (%s)\n", v.Agent, v.Target, v.TargetType)
			chain := ""
			for i, n := range v.Path {
				if i > 0 {
					chain += " --" + v.PathEdgeTypes[i-1] + "--> "
				}
				chain += n
			}
			fmt.Printf("    %s\n", chain)
		}
		fmt.Println()
	}
}
