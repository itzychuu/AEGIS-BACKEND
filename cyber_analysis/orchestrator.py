import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

from .models import CyberAnalysisResult, AnalyzerResult, SecuritySignal
from .dns import DNSAnalyzer
from .http import HTTPAnalyzer
from .tls import TLSAnalyzer
from .redirects import RedirectAnalyzer
from .threat_intel import LocalThreatIntelProvider, ThreatIntelProvider


class CyberOrchestrator:
    """Parallel orchestrator for executing defensive cybersecurity analyzers and aggregating signals."""

    def __init__(
        self,
        dns_analyzer: Optional[DNSAnalyzer] = None,
        http_analyzer: Optional[HTTPAnalyzer] = None,
        tls_analyzer: Optional[TLSAnalyzer] = None,
        redirect_analyzer: Optional[RedirectAnalyzer] = None,
        threat_intel_provider: Optional[ThreatIntelProvider] = None,
        max_workers: int = 5,
    ):
        self.dns_analyzer = dns_analyzer or DNSAnalyzer()
        self.http_analyzer = http_analyzer or HTTPAnalyzer()
        self.tls_analyzer = tls_analyzer or TLSAnalyzer()
        self.redirect_analyzer = redirect_analyzer or RedirectAnalyzer()
        self.threat_intel_provider = threat_intel_provider or LocalThreatIntelProvider()
        self.max_workers = max_workers

    def analyze(self, url: str) -> CyberAnalysisResult:
        start_time = time.perf_counter()

        dns_res = AnalyzerResult()
        http_res = AnalyzerResult()
        tls_res = AnalyzerResult()
        redirect_res = AnalyzerResult()
        threat_intel_res = AnalyzerResult()

        tasks = {
            "dns": lambda: self.dns_analyzer.analyze(url),
            "http": lambda: self.http_analyzer.analyze(url),
            "tls": lambda: self.tls_analyzer.analyze(url),
            "redirects": lambda: self.redirect_analyzer.analyze(url),
            "threat_intel": lambda: self.threat_intel_provider.lookup_url(url),
        }

        results: Dict[str, AnalyzerResult] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_key = {
                executor.submit(func): key for key, func in tasks.items()
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    results[key] = future.result()
                except Exception as e:
                    results[key] = AnalyzerResult(
                        available=False,
                        status="error",
                        errors=[f"Analyzer '{key}' failed unexpectedly: {str(e)}"],
                    )

        dns_res = results.get("dns", dns_res)
        http_res = results.get("http", http_res)
        tls_res = results.get("tls", tls_res)
        redirect_res = results.get("redirects", redirect_res)
        threat_intel_res = results.get("threat_intel", threat_intel_res)

        # Aggregate all emitted security signals
        aggregated_signals: List[SecuritySignal] = []
        for r in (dns_res, http_res, tls_res, redirect_res, threat_intel_res):
            if r and r.signals:
                aggregated_signals.extend(r.signals)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return CyberAnalysisResult(
            dns=dns_res,
            http=http_res,
            tls=tls_res,
            redirects=redirect_res,
            threat_intel=threat_intel_res,
            signals=aggregated_signals,
            total_time_ms=elapsed_ms,
        )
