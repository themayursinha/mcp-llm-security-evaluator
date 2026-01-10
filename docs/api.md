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
