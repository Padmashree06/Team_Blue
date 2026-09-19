# SecureMCP

A secure Model Context Protocol (MCP) gateway and execution environment designed to validate security policies, detect prompt injection attacks and isolate code execution inside multi-language sandboxes.

## Features

- **Secure MCP Implementation:** Provides a structured `secure-mcp` abstraction layer for managing host-agent communications.
- **Prompt Injection Detection:** Inspects operational runtime inputs and incoming agent data against behavioral rules to block prompt overrides.
- **Dynamic Policy Enforcement:** Configures security limits through a structured `security.config.json` schema to govern runtime operations and allowed actions.
- **Multi-Language Sandboxing:** Evaluates and isolates code executions across environments via Go  sandboxing layers (`sandbox.go`).

## File Architecture

- `main.go`: Entry point initializing the application lifecycle and secure pipeline.
- `secure-mcp`: Core implementation handling Model Context Protocol integrations safely.
- `policy.go` & `security.config.json`: Definition and schema parsing for security configuration boundaries.
- `prompt-injection.go`: Logic Engine dedicated to parsing inputs for runtime injection payloads.
- `sandbox.go`: Cross-runtime containment for safe execution of dynamic workloads.

## Prerequisites

- **Go:** Version 1.20 or higher
