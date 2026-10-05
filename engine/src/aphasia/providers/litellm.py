"""LiteLLM-backed attacker provider: one interface to many LLM backends.

The model string selects the provider (e.g. ollama/llama3.2:1b, gpt-4o-mini,
anthropic/claude-3-5-haiku, groq/llama-3.1-8b-instant). Credentials and bases come
from litellm's usual env vars (OPENAI_API_KEY, ANTHROPIC_API_KEY, OLLAMA_API_BASE, ...)
or the api_base argument.
"""
from aphasia.providers.base import ProviderError
from aphasia.types import Step, Turn


class LiteLLMProvider:
    def __init__(self, model: str, api_base: str | None = None, timeout: float = 60.0):
        self.model = model
        self.api_base = api_base
        self.timeout = timeout

    def plan(self, goal: str, history: list[Turn]) -> Step:
        try:
            import litellm
        except ImportError as e:  # pragma: no cover - litellm is a core dep
            raise ProviderError("litellm is not installed; `pip install litellm`") from e

        messages = [{"role": t.role, "content": t.content} for t in history]
        messages.append({"role": "user", "content": goal})
        kwargs = {"model": self.model, "messages": messages, "timeout": self.timeout}
        if self.api_base:
            kwargs["api_base"] = self.api_base
        try:
            resp = litellm.completion(**kwargs)
            text = resp["choices"][0]["message"]["content"]
        except ProviderError:
            raise
        except Exception as e:  # litellm raises many provider-specific error types
            raise ProviderError(f"litellm request failed: {e}") from e
        if not isinstance(text, str) or not text.strip():
            raise ProviderError("litellm returned no content")
        return Step(kind="say", channel="direct", payload=text)
