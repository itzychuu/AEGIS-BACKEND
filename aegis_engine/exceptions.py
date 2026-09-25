class EngineError(Exception):
    """Base exception class for Aegis Engine errors."""
    pass


class RiskScoringError(EngineError, ValueError):
    """Raised when risk score calculation fails or encounters invalid input."""
    pass


class DecisionError(EngineError, ValueError):
    """Raised when classification decision engine encounters an invalid score."""
    pass
