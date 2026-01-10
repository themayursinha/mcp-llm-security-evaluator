# Troubleshooting Guide

Common issues and solutions for the MCP LLM Security Evaluator.

## 1. LLM Client Initialization Failure

**Problem**: `ValueError: Unknown provider: ...` or `ImportError: OpenAI package not available.`
**Solution**:
- Ensure you have installed the requirements: `pip install -r requirements.txt`.
- Check your `.env` file for the correct provider name and API key.
- If using OpenAI/Anthropic, ensure the respective environment variables are set.

## 2. Redaction Not Working as Expected

**Problem**: Sensitive data is not being redacted in the reports.
**Solution**:
- Check the regex patterns in `app/security/redaction.py`.
- Ensure the data matches the regex.
- Try running with `--verbose` to see raw LLM outputs vs redacted outputs in logs.

## 3. Reports Not Being Generated

**Problem**: No files are appearing in the `reports/` directory.
**Solution**:
- Check the write permissions for the `reports/` folder.
- Verify `REPORT_FORMAT` in your `.env` or the `--format` CLI flag.
- Check `logs/evaluator.log` for any exceptions during the report generation phase.

## 4. CI/CD Failures

**Problem**: GitHub Actions workflow fails on "Run tests" or "Lint".
**Solution**:
- Run `black .`, `flake8 .`, and `mypy .` locally to find formatting/type issues.
- Ensure all tests pass locally by running `pytest`.
- Check if your `prompts.yaml` is valid YAML.

## 5. Floating Point Assertion Errors in Tests

**Problem**: Tests like `test_f1_score_calculation` fail with minor precision differences.
**Solution**:
- Use `pytest.approx()` when comparing floating point numbers in tests.
- This is already handled in the core codebase, but check any custom tests you've added.
