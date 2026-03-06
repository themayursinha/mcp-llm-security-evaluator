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

## CLI Overrides
CLI flags override environment defaults when applicable.

Examples:
```bash
python -m app.main --provider mock --format html
python -m app.main --provider ollama --model llama3 --base-url http://localhost:11434
python -m app.main --quick --no-cache
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
