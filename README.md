# MCP LLM Security Evaluator

Tooling to benchmark how safely a Large Language Model behaves when it is wired into the Model Context Protocol (MCP) and given access to external data. The evaluator runs redaction trials, scans repository fixtures for unsafe responses, and assembles a security scorecard with actionable recommendations.

- **Redaction Assurance** — Detects sensitive strings, scrubs them with reusable patterns, and compares pre/post redaction model behaviour.
- **Repository Exercises** — Feeds code and documentation fixtures to the model to surface leakage risks while tracking file-level metrics.
- **Security Scoring & Reports** — Rolls individual test metrics into summary JSON and HTML reports saved in `reports/`.
- **MCP Integration Testing** — Evaluates LLM security when accessing external tools/data via Model Context Protocol.
- **Extensible LLM Client** — Swap in real MCP-aware LLM providers by extending `evaluator/llm.py`.

## Architecture at a Glance
```
mcp-llm-security-evaluator/
├── .github/
│   └── workflows/
│       └── ci.yml                    # CI/CD workflow
├── app/
│   ├── main.py                      # CLI entry point and report orchestration
│   ├── config.py                    # Configuration management (Phase 2)
│   ├── logging_config.py            # Logging configuration (Phase 2)
│   ├── config_validator.py         # Configuration validation (Phase 2)
│   ├── templates/                  # HTML report templates (Phase 2)
│   │   ├── base.html
│   │   ├── report.html
│   │   └── components/
│   └── security/
│       └── redaction.py             # Pattern-based redaction utilities
├── evaluator/
│   ├── runner.py                    # SecurityEvaluator suite orchestrator
│   ├── metrics.py                   # Metric calculations and report builder
│   ├── llm.py                       # Pluggable LLM client abstraction
│   └── mcp_client.py                # MCP security testing
├── tests/                           # pytest suite covering critical components
├── docs/                            # Documentation (Phase 2)
├── logs/                            # Log files (gitignored, Phase 2)
├── data/                            # Sample repositories used by default tests
├── reports/                         # JSON and HTML reports written at runtime
├── .env.example                     # Environment variable template (Phase 2)
├── prompts.yaml                     # Test prompts configuration
└── requirements.txt                 # Dependencies
```

## Prerequisites
- Python 3.11+
- `pip` for dependency installation
- (Optional) Access credentials for whichever LLM provider you wire into `LLMClient` (OpenAI, Anthropic, etc.)

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The repo ships with a stubbed `LLMClient` that echoes prompts. Replace it with a real client (OpenAI, Anthropic, local MCP toolchains, etc.) before running production scenarios.

## Configuration

### Environment Variables

Create a `.env` file in the project root (see `.env.example` for template):

```bash
# Required (for production use)
OPENAI_API_KEY=your_openai_key_here        # If using OpenAI provider
ANTHROPIC_API_KEY=your_anthropic_key_here  # If using Anthropic provider

# Optional
LOG_LEVEL=INFO                              # DEBUG, INFO, WARNING, ERROR, CRITICAL
DEFAULT_MODEL=gpt-3.5-turbo                # Default LLM model
MAX_TOKENS=1000                             # Default max tokens
REPORT_FORMAT=both                          # json, html, or both
SECURITY_THRESHOLD=70                       # Minimum security score threshold
LOG_FILE=logs/evaluator.log                 # Log file path
LOG_ROTATION=true                           # Enable log rotation
LOG_MAX_SIZE=10                             # Max log file size (MB)
LOG_BACKUP_COUNT=5                          # Number of backup log files
```

The evaluator will automatically load these variables on startup. Environment variables override `.env` file values, making it easy to use in containerized deployments.

### Prompts Configuration

Edit `prompts.yaml` to customize test scenarios, prompts, and evaluation criteria. See the [PRD](prd.md) for detailed configuration options.

## Usage
Run the evaluator from the project root:
```bash
python -m app.main [OPTIONS]
```

### Command Line Options

| Flag | Description |
|------|-------------|
| `--config` | Path to the prompts/test configuration YAML (defaults to `prompts.yaml`). |
| `--output-dir` | Directory where reports are saved (defaults to `reports/`). |
| `--format` | Report format: `json`, `html`, or `both` (default: `both`). |
| `--quick` | Skip repository walkthroughs and only run redaction exercises. |
| `--verbose` / `-v` | Print additional diagnostics while the suite runs. |
| `--provider` | LLM provider: `auto`, `openai`, `anthropic`, or `mock` (default: `auto`). |
| `--model` | Specific model to use (e.g., `gpt-4`, `claude-3-sonnet`). |
| `--max-tokens` | Maximum tokens for LLM responses (default: 1000). |

Example quick run:
```bash
python -m app.main --quick -v
```

### What happens during a run?
1. Load configuration from `prompts.yaml` and environment variables (`.env` file).
2. Execute redaction tests to evaluate how often leaked secrets persist after sanitisation.
3. (Unless `--quick`) Traverse repository fixtures (`data/repoA`, `data/repoB`) and probe the model for leakage.
4. Run MCP security tests to evaluate tool access security and privilege escalation risks.
5. Aggregate metrics—precision, recall, effectiveness scores, leakage counts—and package them into timestamped reports.
6. Generate JSON and/or HTML reports (based on `--format` flag) with interactive visualizations.
7. Emit a console summary and a pass/fail exit code (score below threshold exits with status `1`).

Reports are saved as `reports/security_report_YYYYMMDD_HHMMSS.json` and/or `reports/security_report_YYYYMMDD_HHMMSS.html`. These files contain the raw metrics plus actionable recommendations whenever thresholds are missed. HTML reports include interactive charts, dark/light theme support, and export functionality.

## Configuration & Extensibility

- **Environment Variables**: Configure via `.env` file (see Configuration section above). Supports all major settings including API keys, logging, and report formats.
- **Prompts**: Edit `prompts.yaml` to add or tune evaluation prompts. Supports multiple configuration profiles (default, quick, custom).
- **Sample data**: Drop additional fixtures into `data/` and update `SecurityEvaluator` to point at them.
- **Redaction logic**: Extend `app/security/redaction.py` with new patterns or categories; helper functions like `detect_sensitive_data` make it easy to audit coverage.
- **Report templates**: Customize HTML reports by editing templates in `app/templates/`.
- **LLM integration**: Replace the body of `LLMClient.generate` with calls to your MCP-enabled provider, handling authentication via environment variables or secrets managers.

## Testing

Run the full test suite with pytest:
```bash
pytest
```

Tests cover redaction correctness, security metric calculations, and high-level evaluator flows. Add integration tests whenever you introduce a new provider or data source.

### CI/CD Integration

The project includes GitHub Actions workflows for automated testing:
- Runs on pull requests and pushes to main branch
- Tests across Python 3.11 and 3.12
- Code quality checks (linting, formatting, type checking)
- Generates and uploads HTML reports as artifacts

See `.github/workflows/ci.yml` for details.

## Project Status

**Phase 1: Core Framework** ✅ **Completed**
- Basic evaluation engine with redaction, repository, and MCP security testing
- JSON report generation
- Multiple LLM provider support (OpenAI, Anthropic, Mock)
- Comprehensive test suite

**Phase 2: Production Readiness Enhancements** 🚧 **In Progress**
- HTML report generation with interactive visualizations
- Environment variable configuration
- CI/CD integration
- Enhanced logging and observability
- Expanded configuration management

See [`prd.md`](prd.md) for detailed requirements and implementation status.

## License
Released under the MIT License. See `LICENSE` for details.
