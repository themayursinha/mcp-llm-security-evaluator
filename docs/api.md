# API Guide

The project exposes a small FastAPI service for running evaluations remotely and browsing persisted reports.

## Start the Server
```bash
python -m app.main --server --host 127.0.0.1 --port 8000
```

## Authentication
API auth is optional and disabled by default.

Enable it with:
- `API_AUTH_REQUIRED=true`
- `API_KEY=your-shared-secret`

When enabled, send the key with the `X-API-Key` header.

## Endpoints

### `GET /health`
Basic readiness check.

Response:
```json
{
  "status": "healthy",
  "timestamp": "2026-03-06T18:00:00.000000"
}
```

### `POST /evaluate`
Start a background evaluation.

Request body:
```json
{
  "profile": "default",
  "provider": "mock",
  "model": null
}
```

Example:
```bash
curl \
  -X POST http://127.0.0.1:8000/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"profile":"default","provider":"mock"}'
```

Authenticated example:
```bash
curl \
  -X POST http://127.0.0.1:8000/evaluate \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-shared-secret' \
  -d '{"profile":"default","provider":"mock"}'
```

### `GET /reports`
Return summary rows for persisted reports.

Query params:
- `offset`
- `limit`

### `GET /reports/{report_id}`
Return the full stored report JSON for one evaluation.

### `GET /trends`
Return historical overall and MCP scores.

### `GET /monitor`
Serve the built-in monitoring UI.

### `WS /ws/events`
Broadcast progress and completion events to the monitor UI.

## Report Shape
Stored reports use the same generated report shape as the CLI:
- `evaluation_summary`
- `provider_info`
- `redaction_analysis`
- `repository_analysis`
- `mcp_analysis`
- `overall_security_score`
- `recommendations`

## Notes
- The monitor UI is intended for local or trusted-network use.
- Response caching and report history are stored in `data/evaluator_history.db`.
- For programmatic integrations, treat the docs in this folder as the current contract instead of older planning notes in `prd.md`.
