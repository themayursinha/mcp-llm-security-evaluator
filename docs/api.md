# API Documentation

The MCP LLM Security Evaluator can be used programmatically via its Python API.

## SecurityEvaluator Class

The main orchestrator located in `evaluator/runner.py`.

### `SecurityEvaluator.__init__(config_path="prompts.yaml", llm_provider="auto", **llm_kwargs)`
Initializes the evaluator.
- `config_path`: Path to the YAML configuration.
- `llm_provider`: "openai", "anthropic", "mock", or "auto".
- `**llm_kwargs`: Additional arguments passed to the LLM client (e.g., `model="gpt-4"`).

### `SecurityEvaluator.run_evaluation_suite()` (Async)
Runs the full suite of redaction, repository, and MCP tests.
- **Returns**: `Dict[str, Any]` containing all results and a summary.

### `SecurityEvaluator.run_evaluation_suite_sync()`
Synchronous wrapper for `run_evaluation_suite()`.

## LLMClient Class

Located in `evaluator/llm.py`.

### `LLMClient.generate(prompt, **kwargs)` (Async)
Generates a response from the configured LLM.
- `prompt`: The text prompt.
- `**kwargs`: Generation parameters (e.g., `max_tokens`, `temperature`).
- **Returns**: `str` response.

## DataRedactor Class

Located in `app/security/redaction.py`.

### `DataRedactor.redact(text, custom_patterns=None)`
Redacts sensitive information from the given text.
- `text`: Input string.
- `custom_patterns`: Optional dictionary of replacement regexes.
- **Returns**: `str` redacted text.
## REST API

The evaluator includes a FastAPI-based REST API for remote execution and history tracking.

### Starting the Server
```bash
python -m app.main --server --port 8000
```

### Endpoints

#### `POST /evaluate`
Trigger a new security evaluation in the background.
- **Parameters**: `profile`, `provider`, `model` (optional).
- **Example**: `curl -X POST "http://localhost:8000/evaluate?profile=quick&provider=mock"`

#### `GET /reports`
List all historical evaluation reports (summary only).
- **Parameters**: `offset`, `limit` (optional).
- **Example**: `curl http://localhost:8000/reports`

#### `GET /reports/{report_id}`
Retrieve the full JSON report for a specific evaluation.
- **Example**: `curl http://localhost:8000/reports/1`

#### `GET /trends`
Get historical security score trends for analysis.
- **Example**: `curl http://localhost:8000/trends`

#### `GET /monitor` (Web UI)
Access the live security monitoring dashboard with real-time event updates.

#### `WS /ws/events`
WebSocket endpoint for real-time evaluation status and progress updates.

#### `GET /health`
API health check.

## Performance and Scale Features

### LLM Response Caching
By default, the evaluator caches LLM responses in the SQLite database (`data/evaluator_history.db`). This significantly speeds up repeated evaluations and reduces API costs.
- Disable via CLI: `--no-cache`
- Programmatic: Pass `use_cache=False` to `generate()`

### Local Model Support
Support for **Ollama** allows for 100% local, air-gapped security evaluations.
- Start Ollama server locally.
- Run with: `--provider ollama --model llama3 --base-url http://localhost:11434`
