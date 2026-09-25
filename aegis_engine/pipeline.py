from typing import Optional
from .engine import AegisEngine, AnalysisResult


class AnalysisPipeline:
    """Orchestration pipeline boundary for AEGIS security analysis.

    Provides a clean extension interface for future phases (Phase 3 cybersecurity
    deep analysis, Phase 4 local AI analysis) without modifying engine core.
    """

    def __init__(self, engine: Optional[AegisEngine] = None):
        self.engine = engine or AegisEngine()

    def execute(self, url: str) -> AnalysisResult:
        """Run the complete analysis pipeline for a URL."""
        # Phase 2 pipeline: engine analysis (Trust Cache -> ML -> Risk -> Decision)
        result = self.engine.analyze(url)

        # Future Extension Points:
        # Phase 3: result = self._apply_cybersecurity_tools(url, result)
        # Phase 4: result = self._apply_local_ai_explanation(url, result)

        return result


def run_analysis(url: str, engine: Optional[AegisEngine] = None) -> AnalysisResult:
    """Convenience function to run the Aegis analysis pipeline."""
    pipeline = AnalysisPipeline(engine=engine)
    return pipeline.execute(url)
