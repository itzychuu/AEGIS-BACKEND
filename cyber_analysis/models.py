from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict


class SecuritySeverity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecuritySignal:
    """Represents an evidence-backed security observation emitted by an analyzer."""
    source: str          # "dns", "http", "tls", "redirect", "threat_intel"
    type: str            # e.g., "certificate_expired", "known_malicious_match"
    severity: str        # "info", "low", "medium", "high", "critical"
    description: str
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalyzerResult:
    """Standardized result returned by individual cybersecurity analyzers."""
    available: bool = True
    status: str = "success"  # "success", "error", "timeout", "ssrf_blocked", "not_configured", "not_applicable"
    data: Dict[str, Any] = field(default_factory=dict)
    signals: List[SecuritySignal] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["signals"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.signals]
        return d


@dataclass
class CyberAnalysisResult:
    """Combined output from all cybersecurity analyzers."""
    dns: AnalyzerResult = field(default_factory=AnalyzerResult)
    http: AnalyzerResult = field(default_factory=AnalyzerResult)
    tls: AnalyzerResult = field(default_factory=AnalyzerResult)
    redirects: AnalyzerResult = field(default_factory=AnalyzerResult)
    threat_intel: AnalyzerResult = field(default_factory=AnalyzerResult)
    signals: List[SecuritySignal] = field(default_factory=list)
    total_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dns": self.dns.to_dict(),
            "http": self.http.to_dict(),
            "tls": self.tls.to_dict(),
            "redirects": self.redirects.to_dict(),
            "threat_intel": self.threat_intel.to_dict(),
            "signals": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.signals],
            "total_time_ms": self.total_time_ms,
        }
