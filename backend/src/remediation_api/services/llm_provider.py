from abc import ABC, abstractmethod
from typing import Optional
from agno.models.base import Model
from agno.models.deepseek import DeepSeek
from ..config import settings

class LLMProvider(ABC):
    """Abstract base class for LLM providers to ensure extensibility."""
    
    @abstractmethod
    @abstractmethod
    def get_model(self, model_id: Optional[str] = None) -> Model:
        """
        Returns a configured Agno Model instance.
        
        Args:
            model_id (Optional[str]): The specific model identifier (e.g., 'gpt-4', 'deepseek-chat').

        Returns:
            Model: The configured LLM model instance.
        """
        pass

class DeepSeekProvider(LLMProvider):
    """DeepSeek implementation."""
    
    def get_model(self, model_id: Optional[str] = None) -> Model:
        """
        Returns a DeepSeek model instance.

        Args:
            model_id (Optional[str]): Defaults to 'deepseek-chat' if not provided.

        Returns:
            Model: A DeepSeek model instance configured with the API key.
        """
        # Default to deepseek-chat if not specified
        mid = model_id or "deepseek-chat"
        return DeepSeek(
            id=mid,
            api_key=settings.DEEPSEEK_API_KEY
        )

class MockProvider(LLMProvider):
    """Mock implementation for local testing without API credits."""
    
    def get_model(self, model_id: Optional[str] = None) -> Model:
        """
        Returns a Mock model instance for local testing.

        Args:
            model_id (Optional[str]): Ignored in mock provider.

        Returns:
            Model: A dummy DeepSeek model instance.
        """
        # Returns a DeepSeek model configured with dummy data
        # In actual tests, we will likely patch the Agent.run method
        # so this is mostly a placeholder to satisfy dependency injection.
        return DeepSeek(
            id="mock-model",
            api_key="mock-key"
        )

def get_provider() -> LLMProvider:
    """Factory to get the configured provider."""
    # Use DeepSeek if key is configured, regardless of env
    if settings.DEEPSEEK_API_KEY:
        return DeepSeekProvider()
        
    if settings.APP_ENV == "local_mock":
        return MockProvider()
    return DeepSeekProvider()
