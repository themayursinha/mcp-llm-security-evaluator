import os
import asyncio
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from app.logging_config import get_logger

# Optional imports for LLM providers
try:
    import openai

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from app.database import get_cached_response, save_to_cache

logger = get_logger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate a response from the LLM."""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the name of the provider."""
        pass


class MockLLMProvider(LLMProvider):
    """Mock LLM provider for testing."""

    def __init__(self, delay: float = 0.1, **kwargs):
        self.delay = delay
        # Accept any additional kwargs but ignore them

    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate a deterministic safe response for local smoke tests."""
        await asyncio.sleep(self.delay)  # Simulate API delay

        prompt_lower = prompt.lower()
        if any(
            token in prompt_lower
            for token in [
                "sudo",
                "elevated privileges",
                "administrator",
                "bypass security",
                "protected files",
            ]
        ):
            return "Mock provider refusal: unsafe or privileged actions are not allowed."

        if "stateful exfiltration" in prompt_lower or "database_query" in prompt_lower:
            if "Result for database_query" in prompt:
                return (
                    "I got the super_secret_password_123. "
                    '<tool_call>{"name": "web_search", "parameters": '
                    '{"query": "super_secret_password_123"}}</tool_call>'
                )
            return (
                "Let me check the database. "
                '<tool_call>{"name": "database_query", "parameters": '
                '{"query": "SELECT * FROM users", "database": "main"}}</tool_call>'
            )

        if any(
            token in prompt_lower
            for token in ["api key", "password", "secret", "token", "ssn", "email"]
        ):
            return "Mock provider response: sensitive details were detected and omitted."

        return "Mock provider response: request acknowledged for smoke testing."

    def get_provider_name(self) -> str:
        return "mock"


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI package not available. Install with: pip install openai")

        self.client = openai.AsyncOpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model
        self.max_retries = 3
        self.retry_delay = 1.0

    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate a response using OpenAI API."""
        max_tokens = kwargs.get("max_tokens", 1000)
        temperature = kwargs.get("temperature", 0.7)

        for attempt in range(self.max_retries):
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                content = response.choices[0].message.content
                return content if content is not None else ""
            except Exception as e:
                logger.warning(f"OpenAI API attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                else:
                    raise
        return ""

    def get_provider_name(self) -> str:
        return f"openai-{self.model}"


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-sonnet-20240229"):
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "Anthropic package not available. Install with: pip install anthropic"
            )

        self.client = anthropic.AsyncAnthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = model
        self.max_retries = 3
        self.retry_delay = 1.0

    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate a response using Anthropic API."""
        max_tokens = kwargs.get("max_tokens", 1000)

        for attempt in range(self.max_retries):
            try:
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                # Anthropic may return non-text content blocks depending on tools/thinking mode.
                content_block = response.content[0]
                content_text = getattr(content_block, "text", None)
                if isinstance(content_text, str):
                    return content_text
                return str(content_block)
            except Exception as e:
                logger.warning(f"Anthropic API attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2**attempt))
                else:
                    raise
        return ""

    def get_provider_name(self) -> str:
        return f"anthropic-{self.model}"


class OllamaProvider(LLMProvider):
    """Local Ollama API provider."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3"):
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx package not available. Install with: pip install httpx")

        self.base_url = base_url
        self.model = model
        self.timeout = 60.0

    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate a response using Ollama API."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=True) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": kwargs.get("temperature", 0.7),
                            "num_predict": kwargs.get("max_tokens", 1000),
                        },
                    },
                )
                response.raise_for_status()
                return response.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama API request failed: {e}")
            raise

    def get_provider_name(self) -> str:
        return f"ollama-{self.model}"


class LLMClient:
    """Enhanced LLM client with multiple provider support."""

    def __init__(self, provider: str = "auto", **kwargs):
        self.provider_name = provider
        self.default_generate_kwargs = {
            key: kwargs.pop(key)
            for key in ["max_tokens", "temperature", "use_cache"]
            if key in kwargs
        }
        self.kwargs = kwargs
        self._provider = None
        self._initialize_provider()

    def _initialize_provider(self):
        """Initialize the LLM provider based on configuration."""
        if self.provider_name == "auto":
            # Try to auto-detect available providers
            if OPENAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
                self._provider = OpenAIProvider(**self.kwargs)
            elif ANTHROPIC_AVAILABLE and os.getenv("ANTHROPIC_API_KEY"):
                self._provider = AnthropicProvider(**self.kwargs)
            else:
                logger.warning("No API keys found, falling back to mock provider")
                self._provider = MockLLMProvider()
        elif self.provider_name == "openai":
            self._provider = OpenAIProvider(**self.kwargs)
        elif self.provider_name == "anthropic":
            self._provider = AnthropicProvider(**self.kwargs)
        elif self.provider_name == "ollama":
            self._provider = OllamaProvider(**self.kwargs)
        elif self.provider_name == "mock":
            self._provider = MockLLMProvider(**self.kwargs)
        else:
            raise ValueError(f"Unknown provider: {self.provider_name}")

    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate a response from the LLM with optional caching."""
        if self._provider is None:
            raise RuntimeError("Provider not initialized")

        generate_kwargs = {**self.default_generate_kwargs, **kwargs}
        use_cache = generate_kwargs.get("use_cache", True) and not self.is_mock()
        provider_name = self.get_provider_name()
        model_name = getattr(self._provider, "model", "default")

        if use_cache:
            cached = get_cached_response(provider_name, model_name, prompt, generate_kwargs)
            if cached:
                logger.debug(f"Cache hit for {provider_name}")
                return cached

        response = await self._provider.generate(prompt, **generate_kwargs)

        if use_cache and response:
            save_to_cache(provider_name, model_name, prompt, response, generate_kwargs)

        return response

    def generate_sync(self, prompt: str, **kwargs) -> str:
        """Synchronous wrapper for generate method."""
        return asyncio.run(self.generate(prompt, **kwargs))

    def get_provider_name(self) -> str:
        """Get the name of the current provider."""
        if self._provider is None:
            return "unknown"
        return self._provider.get_provider_name()

    def is_mock(self) -> bool:
        """Check if using mock provider."""
        return isinstance(self._provider, MockLLMProvider)


class MultiLLMClient:
    """Client for testing multiple LLMs concurrently."""

    def __init__(self, providers: List[Dict[str, Any]]):
        self.clients = []
        for provider_config in providers:
            provider_name = provider_config.pop("provider", "mock")
            client = LLMClient(provider=provider_name, **provider_config)
            self.clients.append(client)

    async def generate_all(self, prompt: str, **kwargs) -> Dict[str, str]:
        """Generate responses from all configured LLMs."""
        tasks = []
        for client in self.clients:
            task = client.generate(prompt, **kwargs)
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        result: Dict[str, str] = {}
        for i, response in enumerate(responses):
            provider_name = self.clients[i].get_provider_name()
            if isinstance(response, Exception):
                result[provider_name] = f"Error: {response}"
            else:
                result[provider_name] = str(response)

        return result

    def get_provider_names(self) -> List[str]:
        """Get names of all configured providers."""
        return [client.get_provider_name() for client in self.clients]
