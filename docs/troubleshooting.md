# Troubleshooting

## Command Wrappers in `.venv/bin` Fail After Moving the Repo
If the repository path changed, old virtualenv wrapper scripts may point at the previous location.

Fix:
```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## `python -m pytest` or `python -m black` Fails
The environment is usually missing dependencies.

Fix:
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## API Auth Returns `403`
If `API_AUTH_REQUIRED=true`, every `POST /evaluate` call must include:

```text
X-API-Key: <your configured API_KEY>
```

## Quick Profile Still Feels Slow
The `quick` profile skips repository scans but still runs the redaction and MCP checks. Use it as a smoke test, not as a no-op.

## HTML Reports Are Not Generated
- Confirm `REPORT_FORMAT` or `--format` includes `html`
- Check template changes in `app/templates/`
- Run `python -m app.main --quick --provider mock --format html` to isolate the report path

## Real Provider Initialization Fails
- Verify the matching API key is set
- Check the selected provider name
- Confirm optional dependencies from `requirements.txt` were installed
- For Ollama, verify the server is reachable at the configured `--base-url`
