class AIError(Exception):
    """Base exception for Local AI module."""
    pass


class AIProviderError(AIError):
    """Raised when an AI provider API request fails."""
    pass


class AIParserError(AIError):
    """Raised when parsing or validating raw LLM response fails."""
    pass


class AIModelNotFoundError(AIError):
    """Raised when the configured AI model is missing from local runtime."""
    pass


class AITimeoutError(AIError):
    """Raised when AI provider request times out."""
    pass


class AIDisabledError(AIError):
    """Raised when AI processing is requested while disabled."""
    pass
