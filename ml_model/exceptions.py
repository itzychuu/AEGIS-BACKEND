class MLError(Exception):
    """Base exception class for all AEGIS ML errors."""
    pass


class ModelNotFoundError(MLError, FileNotFoundError):
    """Raised when the model artifact file cannot be found."""
    pass


class CorruptModelError(MLError):
    """Raised when the model artifact is corrupt or cannot be deserialized."""
    pass


class InvalidArtifactError(MLError, ValueError):
    """Raised when the model artifact is missing expected internal components."""
    pass


class InvalidURLError(MLError, ValueError):
    """Raised when the provided input URL is invalid or malformed."""
    pass


class IncompatibleSchemaError(MLError, ValueError):
    """Raised when extracted features do not match expected model schema."""
    pass


class PredictionError(MLError):
    """Raised when prediction inference fails."""
    pass
