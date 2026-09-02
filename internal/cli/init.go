package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const exampleConfig = `# AgentGraph configuration
# Model your AI agents, the tools they use, and the infrastructure those
# tools can reach. Then run: agentgraph scan

agents:
  - id: finance-agent
    name: Finance Agent
    criticality: 60
    metadata:
      internet_access: true
      requires_approval: false

  - id: calendar-assistant
    name: Calendar Assistant
    criticality: 10
    metadata:
      internet_access: false
      requires_approval: true

mcp_servers:
  - id: github-mcp
    name: GitHub MCP
    metadata:
      trust_level: high

tools:
  - id: shell.execute
    name: Shell Execution
    metadata:
      risk: critical

identities:
  - id: service-account-17
    name: Deploy Service Account
    metadata:
      privilege: write

secrets:
  - id: aws-deploy-token
    name: AWS Deploy Token
    metadata:
      type: aws_access_key
      location: ci-pipeline

repositories:
  - id: payments-repository
    name: Payments Repository
    metadata:
      environment: production

ci_pipelines:
  - id: production-ci
    name: Production CI
    metadata:
      environment: production

cloud_roles:
  - id: aws-deploy-role
    name: AWS Deploy Role
    provider: aws
    metadata:
      privilege: admin
      environment: production

databases:
  - id: production-database
    name: Production Database
    criticality: 95
    metadata:
      environment: production

# Designate your most critical resources.
crown_jewels:
  - production-database

relationships:
  - source: finance-agent
    target: github-mcp
    type: USES

  - source: github-mcp
    target: payments-repository
    type: CAN_WRITE
    confidence: 1.0

  - source: payments-repository
    target: production-ci
    type: TRIGGERS

  - source: production-ci
    target: aws-deploy-token
    type: CONTAINS_SECRET

  - source: aws-deploy-token
    target: aws-deploy-role
    type: AUTHENTICATES_AS

  - source: aws-deploy-role
    target: production-database
    type: CAN_ACCESS

  - source: calendar-assistant
    target: github-mcp
    type: USES
    confidence: 0.4
`

func newInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a starter agentgraph.yaml configuration",
		Run: func(cmd *cobra.Command, args []string) {
			path := resolveConfigPath()
			if fileExists(path) {
				fmt.Printf("error: %s already exists\n", path)
				os.Exit(1)
			}
			if err := os.WriteFile(path, []byte(exampleConfig), 0644); err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Created %s\n\nNext steps:\n", path)
			fmt.Printf("  agentgraph scan\n")
			fmt.Printf("  agentgraph paths --from finance-agent\n")
			fmt.Printf("  agentgraph blast-radius finance-agent\n")
		},
	}
}
