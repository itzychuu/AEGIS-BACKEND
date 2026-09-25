import os
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Set, Optional, List

from cyber_analysis.models import AnalyzerResult, SecuritySignal, SecuritySeverity
from .base import ThreatIntelProvider

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Local threat intelligence provider using configurable blocklists and allowlists."""

    def __init__(
        self,
        allowlist_path: Optional[Path] = None,
        blocklist_path: Optional[Path] = None,
    ):
        self.allowlist_path = (
            allowlist_path if allowlist_path else DEFAULT_CONFIG_DIR / "allowlist.txt"
        )
        self.blocklist_path = (
            blocklist_path if blocklist_path else DEFAULT_CONFIG_DIR / "blocklist.txt"
        )

        self.allowlist: Set[str] = self._load_list(self.allowlist_path)
        self.blocklist: Set[str] = self._load_list(self.blocklist_path)

    def _load_list(self, path: Path) -> Set[str]:
        entries: Set[str] = set()
        if not path.exists():
            return entries

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line.lower().strip("."))
        except Exception:
            pass
        return entries

    def _match_domain_boundary(self, hostname: str, target_list: Set[str]) -> Optional[str]:
        if not hostname or not target_list:
            return None

        h = hostname.lower().strip(".")
        if h in target_list:
            return h

        # Check subdomains (e.g., "sub.badexample.com" matches "badexample.com")
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain in target_list:
                return parent_domain

        return None

    def lookup_domain(self, domain: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not domain or not isinstance(domain, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["Domain string must be a non-empty string"],
                execution_time_ms=0.0,
            )

        hostname = domain.lower().strip(".")
        signals: List[SecuritySignal] = []

        # Check blocklist first
        block_match = self._match_domain_boundary(hostname, self.blocklist)
        if block_match:
            signals.append(
                SecuritySignal(
                    source="threat_intel",
                    type="known_malicious_match",
                    severity=SecuritySeverity.CRITICAL,
                    description=f"Domain '{hostname}' matched known malicious blocklist entry '{block_match}'",
                    data={"matched_domain": block_match, "list": "blocklist"},
                )
            )

        # Check allowlist
        allow_match = self._match_domain_boundary(hostname, self.allowlist)
        if allow_match:
            signals.append(
                SecuritySignal(
                    source="threat_intel",
                    type="allowlisted_domain",
                    severity=SecuritySeverity.INFO,
                    description=f"Domain '{hostname}' matched trusted allowlist entry '{allow_match}'",
                    data={"matched_domain": allow_match, "list": "allowlist"},
                )
            )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        matched = block_match is not None or allow_match is not None

        return AnalyzerResult(
            available=True,
            status="success",
            data={
                "domain": hostname,
                "matched": matched,
                "is_blocked": block_match is not None,
                "is_allowlisted": allow_match is not None,
                "block_match": block_match,
                "allow_match": allow_match,
                "source": "local_threat_intel",
            },
            signals=signals,
            errors=[],
            execution_time_ms=elapsed_ms,
        )

    def lookup_url(self, url: str) -> AnalyzerResult:
        start_time = time.perf_counter()

        if not url or not isinstance(url, str):
            return AnalyzerResult(
                available=False,
                status="error",
                errors=["URL string must be a non-empty string"],
                execution_time_ms=0.0,
            )

        try:
            parsed = urlparse(url if "://" in url else "https://" + url)
            hostname = (parsed.hostname or "").lower().strip(".")
        except Exception as e:
            return AnalyzerResult(
                available=False,
                status="error",
                errors=[f"Failed to parse URL: {str(e)}"],
                execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
            )

        res = self.lookup_domain(hostname)
        res.data["url"] = url
        res.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return res
