import time
from typing import Optional, Any

from local_ai.config import AIConfig
from local_ai.models import AIAnalysisResult, AIStatus
from local_ai.exceptions import (
    AIError,
    AIProviderError,
    AITimeoutError,
    AIModelNotFoundError,
    AIDisabledError,
)
from local_ai.providers import LocalAIProvider, OllamaProvider
from local_ai.prompts import build_ai_context, build_prompt_messages
from local_ai.parser import parse_ai_response


class LocalAIAnalyzer:
    """Model-agnostic local AI coordinator for security signal correlation and contextual explanations."""

    def __init__(
        self,
        config: Optional[AIConfig] = None,
        provider: Optional[LocalAIProvider] = None,
    ):
        self.config = config or AIConfig()
        if provider is not None:
            self.provider = provider
        elif self.config.provider.lower() == "ollama":
            self.provider = OllamaProvider(
                base_url=self.config.base_url,
                default_model=self.config.model,
            )
        else:
            self.provider = OllamaProvider(
                base_url=self.config.base_url,
                default_model=self.config.model,
            )

    def analyze(self, analysis_result: Any) -> AIAnalysisResult:
        """Analyze security evidence signals from an Aegis AnalysisResult.

        Args:
            analysis_result: An Aegis AnalysisResult instance containing security evidence.

        Returns:
            AIAnalysisResult with summary, correlation, key findings, and uncertainties.
        """
        if not self.config.enabled:
            return AIAnalysisResult(
                available=False,
                status=AIStatus.DISABLED,
                provider=self.provider.name,
                model=self.config.model,
            )

        start_time = time.perf_counter()

        # 1. Health check local runtime
        if not self.provider.health_check():
            return AIAnalysisResult(
                available=False,
                status=AIStatus.UNAVAILABLE,
                provider=self.provider.name,
                model=self.config.model,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                error=f"Local AI runtime '{self.provider.name}' is offline or unreachable at {self.config.base_url}",
            )

        # 2. Check model availability
        if not self.provider.is_model_available(self.config.model):
            return AIAnalysisResult(
                available=False,
                status=AIStatus.MODEL_NOT_FOUND,
                provider=self.provider.name,
                model=self.config.model,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                error=f"Configured AI model '{self.config.model}' is not installed in local runtime",
            )

        # 3. Build controlled context and messages
        try:
            context = build_ai_context(analysis_result)
            messages = build_prompt_messages(context)
        except Exception as e:
            return AIAnalysisResult(
                available=False,
                status=AIStatus.PROVIDER_ERROR,
                provider=self.provider.name,
                model=self.config.model,
                latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
                error=f"Failed to construct AI prompt context: {str(e)}",
            )

        # 4. Generate response with provider
        try:
            raw_response = self.provider.generate(
                messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.timeout,
                model_override=self.config.model,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return parse_ai_response(
                raw_response,
                self.provider.name,
                self.config.model,
                elapsed_ms,
                self.config,
            )

        except AITimeoutError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return AIAnalysisResult(
                available=False,
                status=AIStatus.TIMEOUT,
                provider=self.provider.name,
                model=self.config.model,
                latency_ms=round(elapsed_ms, 2),
                error=str(e),
            )
        except AIModelNotFoundError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return AIAnalysisResult(
                available=False,
                status=AIStatus.MODEL_NOT_FOUND,
                provider=self.provider.name,
                model=self.config.model,
                latency_ms=round(elapsed_ms, 2),
                error=str(e),
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return AIAnalysisResult(
                available=False,
                status=AIStatus.PROVIDER_ERROR,
                provider=self.provider.name,
                model=self.config.model,
                latency_ms=round(elapsed_ms, 2),
                error=str(e),
            )
