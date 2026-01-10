# Extensibility Guide

The MCP LLM Security Evaluator is designed to be pluggable and extensible.

## 1. Adding a New LLM Provider

To add a new provider (e.g., local Llama via Ollama):

1.  Open `evaluator/llm.py`.
2.  Create a new class inheriting from `LLMProvider`.
3.  Implement `generate` and `get_provider_name`.
4.  Update `LLMClient._initialize_provider` to recognize your new provider name.

```python
class OllamaProvider(LLMProvider):
    async def generate(self, prompt: str, **kwargs) -> str:
        # Implement API call to Ollama
        return response
```

## 2. Implementing New Security Metrics

Metrics are calculated in `evaluator/metrics.py`.

1.  Add new metric calculation functions.
2.  Integrate them into `calculate_security_metrics` or `calculate_repository_metrics`.
3.  Update HTML templates in `app/templates/` to visualize the new metrics.

## 3. Adding MCP Tools for Testing

MCP tools for security testing are defined in `evaluator/mcp_client.py`.

1.  Add tool definitions to `SAMPLE_MCP_TOOLS`.
2.  Update `MCPSecurityTester._assess_security_risk` if new risk categories are needed.
3.  Add new test prompts to `test_tool_access_security`.

## 4. Customizing HTML Reports

The HTML reports use Jinja2 templates located in `app/templates/`.

- **base.html**: Global layout, navigation, and theme logic.
- **report.html**: Main dashboard and data visualizations.
- **components/**: Partial templates for specific analysis sections.

Visualizations are powered by Chart.js. You can modify chart configurations in the `<script>` blocks within `report.html`.
