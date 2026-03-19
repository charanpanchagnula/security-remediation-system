from abc import ABC, abstractmethod
from typing import Optional
from agno.models.base import Model
from agno.models.deepseek import DeepSeek
from ..config import settings

class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def get_model(self, model_id: Optional[str] = None) -> Model:
        pass

class DeepSeekProvider(LLMProvider):

    def get_model(self, model_id: Optional[str] = None) -> Model:
        return DeepSeek(
            id=model_id or "deepseek-chat",
            api_key=settings.DEEPSEEK_API_KEY
        )

class AnthropicProvider(LLMProvider):

    def get_model(self, model_id: Optional[str] = None) -> Model:
        from agno.models.anthropic import Claude
        return Claude(
            id=model_id or "claude-sonnet-4-5",
            api_key=settings.ANTHROPIC_API_KEY,
        )

class MockProvider(LLMProvider):
    """Mock implementation for local testing without API credits."""

    def get_model(self, model_id: Optional[str] = None) -> Model:
        return DeepSeek(
            id="mock-model",
            api_key="mock-key"
        )

def get_provider() -> LLMProvider:
    """Factory to get the configured provider. Always uses DeepSeek for server-side remediation."""
    if settings.DEEPSEEK_API_KEY:
        return DeepSeekProvider()
    if settings.APP_ENV == "local_mock":
        return MockProvider()
    return DeepSeekProvider()
