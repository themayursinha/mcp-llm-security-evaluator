# MCP LLM Security Evaluator

Security-focused tooling for testing how an LLM behaves when it is exposed to sensitive text, repository content, and MCP-style tool access. The project can run local smoke tests with a deterministic mock provider or connect to real providers for deeper evaluation.

## What Works Today
- CLI evaluation flow with JSON and HTML reports.
- Redaction tests against synthetic secrets and PII.
- Repository fixture scanning for leakage-style responses.
- MCP tool-risk and privilege-escalation exercises.
- MCP server inventory review from profile or MCP client config-style declarations.
- MCP tool catalog snapshots and baseline diffing for metadata drift.
- MCP policy checks for per-tool authorization, approval metadata, token passthrough,
  and sensitive-to-outbound tool chains.
- Redacted MCP audit events that preserve tool-call evidence for incident review.
- FastAPI service for remote execution and report history.
- SQLite-backed report history and response cache.

## What This Is
- A practical evaluation toolkit for LLM security experiments.
- A companion implementation for MCP supply-chain and control-plane reviews.
- A good fit for demos, CI smoke checks, provider comparison work, and early MCP
  governance experiments.

## What This Is Not
- A complete penetration-testing framework.
- A hosted service or packaged SDK release.
- A guarantee that a model or MCP server is production-safe.

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
python -m app.main --quick --provider mock --format html
```

The mock provider is intended for smoke testing the pipeline. It returns safe deterministic responses so you can validate the evaluator without external API keys.

## Real Provider Run
Create a `.env` file from `.env.example`, then configure the provider you want to use.

```bash
cp .env.example .env
python -m app.main --provider openai --model gpt-4o-mini --format both
```

Supported providers:
- `mock`
- `openai`
- `anthropic`
- `ollama`
- `auto` (prefers configured real providers, otherwise falls back to `mock`)

## CLI Usage
```bash
python -m app.main [OPTIONS]
```

Common options:
- `--quick` uses the `quick` profile and skips repository scans.
- `--format {json,html,both}` controls report output.
- `--provider {auto,openai,anthropic,ollama,mock}` selects the LLM backend.
- `--server` starts the REST API instead of running a CLI evaluation.
- `--no-cache` disables persistent LLM response caching.

The `quick` profile is meant to stay CI-friendly. The broader `default` profile
includes intentionally adversarial MCP control-plane scenarios, including a
stateful exfiltration chain.

## API Usage
Start the API server:

```bash
python -m app.main --server --host 127.0.0.1 --port 8000
```

Trigger an evaluation:

```bash
curl \
  -X POST http://127.0.0.1:8000/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"profile":"default","provider":"mock"}'
```

Optional API auth can be enabled with `API_AUTH_REQUIRED=true` and `API_KEY=...`.

## Reports
- CLI runs write timestamped JSON and/or HTML reports to `reports/`.
- API runs persist reports in `data/evaluator_history.db`.
- The HTML report is designed for sharing results with non-developers.
- MCP report sections include inventory, catalog drift, policy findings, stateful
  tool-chain findings, and redacted audit events.

## Project Layout
```text
app/         CLI, API, templates, config, persistence
evaluator/   Core evaluator, metrics, provider clients, MCP testing
data/        Sample fixtures and SQLite database
docs/        User and operator documentation
tests/       Pytest suite
```

## Development Checks
```bash
python -m black --check app evaluator tests
python -m flake8 app evaluator tests
python -m mypy
python -m pytest --cov=app --cov=evaluator
```

## Documentation
- [Architecture](Architecture.md)
- [API guide](docs/api.md)
- [Configuration guide](docs/configuration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release checklist](RELEASE_CHECKLIST.md)

## Status
The repository is positioned as a shareable, public project with a working mock/demo path and experimental real-provider integrations. Historical planning notes remain in [`prd.md`](prd.md), but the README and `docs/` are the source of truth for current behavior.

## License
Released under the MIT License. See [LICENSE](LICENSE).
