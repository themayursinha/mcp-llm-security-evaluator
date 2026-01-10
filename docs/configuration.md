# Configuration Guide

This guide explains how to configure the MCP LLM Security Evaluator for various testing scenarios.

## 1. Environment Variables (.env)

The evaluator uses a `.env` file for core settings and API keys.

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key for OpenAI provider | None |
| `ANTHROPIC_API_KEY` | API key for Anthropic provider | None |
| `LOG_LEVEL` | Logging verbosity (DEBUG, INFO, etc.) | INFO |
| `REPORT_FORMAT` | output format (json, html, both) | both |
| `SECURITY_THRESHOLD` | Score (0-100) below which CI fails | 70 |
| `LOG_FILE` | Path to log file | logs/evaluator.log |

## 2. Prompts Configuration (prompts.yaml)

The `prompts.yaml` file defines the test scenarios and evaluation profiles.

### Structure
```yaml
version: "2.0"
profiles:
  default:
    description: "Standard suite"
    redaction_tests: [...]
    repository_tests: [...]
    mcp_tests: [...]
```

### Profiles
- **default**: Comprehensive testing including all categories.
- **quick**: Optimized for speed, skips long-running scans.

## 3. Customizing Redaction Patterns

Edit `app/security/redaction.py` to add new regex patterns for sensitive data detection. The `DataRedactor` class maintains the `redaction_patterns` dictionary.

## 4. Running Specific Tests

Use CLI flags to override configuration:
- `--quick`: Skips repository scans.
- `--provider [openai|anthropic|mock]`: Switches LLM backend.
- `--format [json|html]`: Overrides output format.
