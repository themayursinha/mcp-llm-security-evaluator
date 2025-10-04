# MCP LLM Security Evaluator

Tooling to benchmark how safely a Large Language Model behaves when it is wired into the Model Context Protocol (MCP) and given access to external data. The evaluator runs redaction trials, scans repository fixtures for unsafe responses, and assembles a security scorecard with actionable recommendations.

- **Redaction Assurance** — Detects sensitive strings, scrubs them with reusable patterns, and compares pre/post redaction model behaviour.
- **Repository Exercises** — Feeds code and documentation fixtures to the model to surface leakage risks while tracking file-level metrics.
- **Security Scoring & Reports** — Rolls individual test metrics into a summary JSON report saved in `reports/`.
- **Extensible LLM Client** — Swap in real MCP-aware LLM providers by extending `evaluator/llm.py`.

## Architecture at a Glance
```
mcp-llm-security-evaluator/
├─ app/
│  ├─ main.py              # CLI entry point and report orchestration
│  └─ security/
│     └─ redaction.py      # Pattern-based redaction utilities
├─ evaluator/
│  ├─ runner.py            # SecurityEvaluator suite orchestrator
│  ├─ metrics.py           # Metric calculations and report builder
│  └─ llm.py               # Pluggable LLM client abstraction
├─ data/                   # Sample repositories used by default tests
├─ reports/                # JSON reports written at runtime
├─ prompts.yaml            # Default prompt configuration
└─ tests/                  # pytest suite covering the critical components
```

## Prerequisites
- Python 3.11+
- `pip` for dependency installation
- (Optional) Access credentials for whichever LLM provider you wire into `LLMClient`

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The repo ships with a stubbed `LLMClient` that echoes prompts. Replace it with a real client (OpenAI, Anthropic, local MCP toolchains, etc.) before running production scenarios.

## Usage
Run the evaluator from the project root:
```bash
python -m app.main [--config prompts.yaml] [--output-dir reports] [--quick] [--verbose]
```

| Flag | Description |
|------|-------------|
| `--config` | Path to the prompts/test configuration YAML (defaults to `prompts.yaml`). |
| `--output-dir` | Directory where JSON reports are saved (defaults to `reports/`). |
| `--quick` | Skip repository walkthroughs and only run redaction exercises. |
| `--verbose` / `-v` | Print additional diagnostics while the suite runs. |

Example quick run:
```bash
python -m app.main --quick -v
```

### What happens during a run?
1. Load prompts and sample data listed in `prompts.yaml` and `data/`.
2. Execute redaction tests to evaluate how often leaked secrets persist after sanitisation.
3. (Unless `--quick`) Traverse repository fixtures (`data/repoA`, `data/repoB`) and probe the model for leakage.
4. Aggregate metrics—precision, recall, effectiveness scores, leakage counts—and package them into a timestamped JSON report.
5. Emit a console summary and a pass/fail exit code (score below 70 exits with status `1`).

Reports are saved as `reports/security_report_YYYYMMDD_HHMMSS.json`. These files contain the raw metrics plus recommendation strings whenever thresholds are missed.

## Configuration & Extensibility
- **Prompts**: Edit `prompts.yaml` to add or tune evaluation prompts.
- **Sample data**: Drop additional fixtures into `data/` and update `SecurityEvaluator` to point at them.
- **Redaction logic**: Extend `app/security/redaction.py` with new patterns or categories; helper functions like `detect_sensitive_data` make it easy to audit coverage.
- **LLM integration**: Replace the body of `LLMClient.generate` with calls to your MCP-enabled provider, handling authentication via environment variables or secrets managers.

## Testing
Run the full test suite with pytest:
```bash
pytest
```

Tests cover redaction correctness, security metric calculations, and high-level evaluator flows. Add integration tests whenever you introduce a new provider or data source.

## Project Status
This codebase scaffolds the MCP evaluator described in `prd.md`. It includes the orchestration logic, metrics, and redaction engine necessary for experiments; production deployments still need a real LLM backend, richer prompt packs, and hardened report handling.

## License
Released under the MIT License. See `LICENSE` for details.
