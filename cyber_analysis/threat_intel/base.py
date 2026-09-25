from abc import ABC, abstractmethod
from cyber_analysis.models import AnalyzerResult


class ThreatIntelProvider(ABC):
    """Abstract base provider interface for threat intelligence feeds and lookup sources."""

    @abstractmethod
    def lookup_url(self, url: str) -> AnalyzerResult:
        """Lookup threat intelligence for a full URL."""
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> AnalyzerResult:
        """Lookup threat intelligence for a domain or hostname."""
        pass
