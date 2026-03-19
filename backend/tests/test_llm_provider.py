"""
Tests for llm_provider.py.

Critical regression test: ANTHROPIC_API_KEY must never win over DeepSeek,
even if both keys are present. The server-side engine is DeepSeek-only.
"""
from unittest.mock import patch, MagicMock


def _get_provider_with(deepseek_key=None, anthropic_key=None, app_env="local"):
    with patch("remediation_api.services.llm_provider.settings") as mock_settings:
        mock_settings.DEEPSEEK_API_KEY = deepseek_key
        mock_settings.ANTHROPIC_API_KEY = anthropic_key
        mock_settings.APP_ENV = app_env
        from remediation_api.services.llm_provider import get_provider
        return get_provider()


def test_deepseek_provider_when_key_is_set():
    from remediation_api.services.llm_provider import DeepSeekProvider
    provider = _get_provider_with(deepseek_key="sk-test")
    assert isinstance(provider, DeepSeekProvider)


def test_mock_provider_when_no_key_and_local_mock_env():
    from remediation_api.services.llm_provider import MockProvider
    provider = _get_provider_with(deepseek_key=None, app_env="local_mock")
    assert isinstance(provider, MockProvider)


def test_deepseek_is_default_fallback_with_no_key():
    from remediation_api.services.llm_provider import DeepSeekProvider
    provider = _get_provider_with(deepseek_key=None, app_env="production")
    assert isinstance(provider, DeepSeekProvider)


def test_anthropic_provider_never_returned_even_when_both_keys_present():
    """
    Regression: previously ANTHROPIC_API_KEY took priority.
    Now it is ignored — DeepSeek always wins server-side.
    """
    from remediation_api.services.llm_provider import AnthropicProvider
    provider = _get_provider_with(deepseek_key="sk-deepseek", anthropic_key="sk-anthropic")
    assert not isinstance(provider, AnthropicProvider)


def test_anthropic_provider_not_returned_when_only_anthropic_key_present():
    """
    Even with only an Anthropic key and no DeepSeek key,
    we fall through to the DeepSeek default, not Anthropic.
    """
    from remediation_api.services.llm_provider import AnthropicProvider
    provider = _get_provider_with(deepseek_key=None, anthropic_key="sk-anthropic", app_env="local")
    assert not isinstance(provider, AnthropicProvider)


def test_deepseek_provider_get_model_uses_configured_key():
    with patch("remediation_api.services.llm_provider.settings") as mock_settings, \
         patch("remediation_api.services.llm_provider.DeepSeek") as MockDeepSeek:
        mock_settings.DEEPSEEK_API_KEY = "sk-real-key"
        from remediation_api.services.llm_provider import DeepSeekProvider
        provider = DeepSeekProvider()
        provider.get_model()
        MockDeepSeek.assert_called_once_with(id="deepseek-chat", api_key="sk-real-key")


def test_deepseek_provider_get_model_accepts_custom_model_id():
    with patch("remediation_api.services.llm_provider.settings") as mock_settings, \
         patch("remediation_api.services.llm_provider.DeepSeek") as MockDeepSeek:
        mock_settings.DEEPSEEK_API_KEY = "sk-key"
        from remediation_api.services.llm_provider import DeepSeekProvider
        provider = DeepSeekProvider()
        provider.get_model("deepseek-reasoner")
        MockDeepSeek.assert_called_once_with(id="deepseek-reasoner", api_key="sk-key")
