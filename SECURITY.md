# Security Policy

AgentGraph maps sensitive infrastructure metadata: identities, roles,
secret locations, and permission relationships. We hold it to a high
security standard, and we design it so that compromising AgentGraph does
not compromise your infrastructure.

## Design commitments

- **Never stores secret values.** Secrets are modeled as metadata-only
  nodes (name, type, location). The YAML loader redacts forbidden fields
  with a warning, and every connector drops API-provided values at the
  parse boundary (enforced by tests).
- **Read-only connectors.** All integrations use List/Get calls only.
  Run them with read-only credentials — the docs recommend it and the
  tools never need more.
- **No exploitation.** AgentGraph models potential attack paths; it never
  executes them. The runtime detector observes and alerts; it does not
  act.

## Reporting a vulnerability

**Please do not open public issues for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/blackrabbit1x0/agentgraph/security)
2. Click "Report a vulnerability"

Or email the maintainer directly. Please include:

- A description of the issue and its impact
- Steps or a proof of concept
- Affected version (release tag or commit)

You should receive a response within 72 hours. Once the issue is
confirmed, we'll work on a fix and coordinate disclosure with you.

## Scope

In scope: this repository's code and its published release binaries.

Out of scope: vulnerabilities in your own infrastructure that AgentGraph
*reports* (that's the product working), or in dependencies already
triaged as non-exploitable in this context — though we still appreciate
heads-ups about the latter.
