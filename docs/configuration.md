# Configuration Guide

## Environment Variables

Copy `.env.example` to `.env` and change only what you need.

```bash
cp .env.example .env
```

### Provider Settings
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `DEFAULT_MODEL`
- `MAX_TOKENS`

### Reporting
- `REPORT_FORMAT` = `json`, `html`, or `both`
- `SECURITY_THRESHOLD` = exit-code threshold for CLI runs
- `EVALUATOR_DB_PATH` = optional SQLite path for report history and LLM cache

### Logging
- `LOG_LEVEL`
- `LOG_FILE`
- `LOG_ROTATION`
- `LOG_MAX_SIZE`
- `LOG_BACKUP_COUNT`

### API Security
- `API_AUTH_REQUIRED` = `true` or `false`
- `API_KEY` = shared secret required when API auth is enabled
- `API_ALLOWED_ORIGINS` = comma-separated CORS allowlist

Default API CORS values are limited to:
- `http://127.0.0.1:8000`
- `http://localhost:8000`

## Prompt Profiles
`prompts.yaml` defines evaluation profiles.

Current built-in profiles:
- `default` for the broader suite
- `quick` for fast smoke testing without repository scans

## MCP Control-Plane Configuration
Profiles can include MCP review controls alongside prompt tests.

### Server inventory
Use `mcp_servers` for inline server declarations, or `mcp_inventory_paths` for
JSON/YAML files that contain common MCP client config shapes such as
`mcpServers`.

```yaml
mcp_servers:
  filesystem:
    command: "npx"
    args:
      - "@modelcontextprotocol/server-filesystem@1.2.3"
      - "data"
    transport: "stdio"
    version: "1.2.3"
    owner: "security"
    approved: true
```

### Tool catalog baseline
Use `previous_tool_catalog` to compare the current tool metadata against a known
baseline. Diffs include added, removed, and changed tools, with field-level
change hints for descriptions, parameters, annotations, and output schemas.

```yaml
previous_tool_catalog:
  tools:
    - name: "database_query"
      source_server: "prod-db"
      description: "Execute read-only database queries"
      parameters:
        query: "string"
        database: "string"
```

### Configured tools
Profiles can declare tools directly with `mcp_tools`, or attach tools to
`mcp_servers`. Configured tools are added to the current catalog before policy,
catalog-drift, and tool-access checks run.

```yaml
mcp_tools:
  - name: "crm_lookup"
    description: "Read customer CRM records"
    parameters:
      customer_id: "string"

mcp_servers:
  ticketing:
    command: "npx"
    args:
      - "@example/ticketing-mcp@1.0.0"
    approved: true
    tools:
      - name: "ticket_update"
        description: "Update support ticket status"
        parameters:
          ticket_id: "string"
          status: "string"
```

Set `include_sample_tools: false` on a profile when you only want configured
tools in the MCP catalog.

### Policy checks
Use `mcp_policy` to express coarse-grained controls for the evaluator.

```yaml
mcp_policy:
  default_action: "allow"
  require_approval_for_risk:
    - "high"
  require_approval_for_tools:
    - "file_write"
    - "database_query"
  denied_tools:
    - "system_execute"
  block_sensitive_to_outbound: true
  block_token_passthrough: true
```

Policy findings are advisory in the report. Critical and high findings affect
the MCP security score.

## CLI Overrides
CLI flags override environment defaults when applicable.

Examples:
```bash
python -m app.main --provider mock --format html
python -m app.main --provider ollama --model llama3 --base-url http://localhost:11434
python -m app.main --quick --no-cache
python -m app.main --quick --compare-providers mock,ollama --format both
```

## Caching and Persistence
- LLM response cache lives in `data/evaluator_history.db`
- Historical reports are persisted in the same SQLite database
- Generated JSON and HTML reports are written to `reports/`

## Configuration Validation
Startup validation currently checks:
- provider-specific API key requirements
- report format validity
- security threshold range
- log level validity
- API auth consistency (`API_KEY` must exist when auth is enabled)
