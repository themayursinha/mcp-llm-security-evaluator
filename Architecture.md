# Repository Architecture

This document summarizes the main runtime components and how data flows through the MCP LLM Security Evaluator.

## Component Overview

```mermaid
flowchart TB
  subgraph Entry_Points
    CLI[CLI app/main.py]
    API[FastAPI app/api.py]
  end

  subgraph Config
    Prompts[prompts.yaml profiles]
    Env[.env and environment variables]
    ConfigClass[Config + ConfigValidator]
  end

  subgraph Core_Evaluator
    SE[SecurityEvaluator evaluator/runner.py]
    Redaction[Redaction app/security/redaction.py]
    RepoScan[Repository scan data/*]
    MCP[MCPSecurityTester evaluator/mcp_client.py]
    Metrics[evaluator/metrics.py]
  end

  subgraph LLM_Layer
    LLMClient[evaluator/llm.py LLMClient]
    Providers[Providers: OpenAI / Anthropic / Ollama / Mock]
  end

  subgraph Storage_Outputs
    Reports[reports/*.json and *.html]
    Templates[app/templates/*]
    DB[(SQLite data/evaluator_history.db)]
    Cache[(LLM cache table)]
    Logs[logs/*]
  end

  CLI --> ConfigClass
  CLI --> SE
  CLI --> Metrics
  CLI --> Reports
  CLI --> DB

  API --> ConfigClass
  API --> SE
  API --> DB

  ConfigClass --> Env
  SE --> Prompts
  SE --> Redaction
  SE --> RepoScan
  SE --> MCP
  SE --> Metrics
  SE --> LLMClient
  LLMClient --> Providers
  LLMClient --> Cache
  Cache --> DB
  Metrics --> Templates
  Metrics --> Reports
  Redaction --> DB
```

## CLI Evaluation Flow

```mermaid
flowchart TD
  Start[CLI invocation] --> LoadConfig[Load and validate config]
  LoadConfig --> InitEval[Initialize SecurityEvaluator]

  InitEval --> RedactionTests[Run redaction tests]
  InitEval --> RepoTests[Run repository tests]
  InitEval --> MCPTests[Run MCP security tests]

  RedactionTests --> Collect[Collect results]
  RepoTests --> Collect
  MCPTests --> Collect

  Collect --> Report[Generate security report]
  Report --> SaveJSON[Write JSON report to reports/]
  Report --> SaveHTML[Render HTML report via templates]
  Report --> SaveDB[Persist report to SQLite history]

  SaveJSON --> Summary[Print summary and exit code]
  SaveHTML --> Summary
  SaveDB --> Summary
```

## API Flow

```mermaid
flowchart TD
  Client[API client] --> Evaluate[/evaluate]
  Evaluate --> Background[Background task]
  Background --> Eval[SecurityEvaluator]
  Eval --> Report[Generate report]
  Report --> DB[(SQLite history)]
  Background --> WS[WebSocket progress events]

  Client --> Reports[/reports /reports/{id} /trends]
  Reports --> DB

  Client --> UI[/ and /monitor]
  UI --> Templates[app/templates/*]
```

## Database Schema

```mermaid
erDiagram
  EvaluationReport {
    int id PK
    datetime timestamp
    float overall_security_score
    float mcp_security_score
    int leakage_detected
    int total_tests
    float execution_time
    string provider
    boolean is_mock
    string status
    json report_json
  }

  LLMCache {
    int id PK
    string cache_key
    string prompt_hash
    string provider
    string model
    string prompt
    string response
    json parameters
    datetime timestamp
  }
```

## Key Data Artifacts

- Configuration: `prompts.yaml`, `.env`, and environment variables
- Fixtures: `data/` repositories and sample files
- Reports: `reports/*.json` and `reports/*.html`
- History and cache: `data/evaluator_history.db` (SQLModel tables `EvaluationReport` and `LLMCache`)
- Logs: `logs/` based on `app/logging_config.py`
