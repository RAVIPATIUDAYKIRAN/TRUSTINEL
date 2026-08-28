"""
Service implementation of AIThreatAnalysisService that performs AI-assisted
threat analysis based on existing deterministic security evidence.

The AI analyzes existing evidence — it never replaces, overrides, or recalculates
the deterministic trust score or risk level.
"""
import abc
import json
import logging
from typing import Any, Dict, List

import httpx

from app.config.settings import settings
from app.schemas.ssl_analysis import SSLAnalysisResult
from app.schemas.whois_analysis import WHOISAnalysisResult
from app.schemas.header_analysis import HeaderAnalysisResult
from app.schemas.redirect_analysis import RedirectAnalysisResult
from app.schemas.trust_evaluation import TrustEvaluationResult
from app.schemas.ai_threat_analysis import AIThreatAnalysisResult

logger = logging.getLogger("trustinel.services.ai_threat_analysis_service")


# ---------------------------------------------------------------------------
# Provider Abstraction
# ---------------------------------------------------------------------------

class AIThreatProvider(abc.ABC):
    """
    Abstract base interface for AI threat analysis providers.
    Implementations must be stateless and async-safe.
    """

    @abc.abstractmethod
    async def analyze_threat(
        self,
        model: str,
        api_key: str,
        evidence: Dict[str, Any],
    ) -> AIThreatAnalysisResult:
        """
        Sends structured evidence to an AI provider and returns a validated
        AIThreatAnalysisResult. Implementations must raise on failure so caller
        can fall back to deterministic response.
        """
        ...


class OpenAIThreatProvider(AIThreatProvider):
    """
    Concrete provider implementation that calls OpenAI-compatible Chat Completions API
    using httpx.
    """

    API_URL = "https://api.openai.com/v1/chat/completions"
    TIMEOUT_SECONDS = 10.0

    SYSTEM_PROMPT = (
        "You are an expert website security threat analyst. You will receive structured "
        "security evidence from a website analysis system. Your job is to analyze potential "
        "security threats based strictly on the provided evidence.\n\n"
        "STRICT RULES:\n"
        "- Do NOT calculate a new trust score or modify the risk level.\n"
        "- Do NOT invent security findings or threats not present in the evidence.\n"
        "- Use ONLY the supplied evidence to perform your assessment.\n"
        "- Return ONLY valid JSON matching this exact schema:\n"
        '  {"threat_level": "LOW"|"MEDIUM"|"HIGH"|"UNKNOWN", "confidence": 0.0-1.0, '
        '"suspicious_indicators": ["..."], "reasoning": "...", "recommended_action": "..."}\n'
        "- confidence MUST be a float between 0.0 and 1.0.\n"
        "- threat_level MUST be one of 'LOW', 'MEDIUM', 'HIGH', or 'UNKNOWN'.\n"
        "- All fields are required.\n"
    )

    async def analyze_threat(
        self,
        model: str,
        api_key: str,
        evidence: Dict[str, Any],
    ) -> AIThreatAnalysisResult:
        user_message = (
            "Analyze the following website security evidence for potential threats. "
            "Return ONLY the JSON object described in your instructions.\n\n"
            f"Evidence:\n{json.dumps(evidence, default=str)}"
        )

        payload = {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "response_format": {"type": "json_object"},
        }

        async with httpx.AsyncClient(timeout=self.TIMEOUT_SECONDS) as client:
            response = await client.post(
                self.API_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()

        data = response.json()
        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)

        if isinstance(parsed, dict):
            parsed["enabled"] = True

        return AIThreatAnalysisResult.model_validate(parsed)


# ---------------------------------------------------------------------------
# Core Service
# ---------------------------------------------------------------------------

class AIThreatAnalysisService:
    """
    Orchestrates AI-assisted threat analysis using structured security evidence.
    Falls back deterministically if AI is disabled or provider fails.
    """

    _providers: Dict[str, AIThreatProvider] = {
        "openai": OpenAIThreatProvider(),
    }

    async def analyze(
        self,
        trust_evaluation: TrustEvaluationResult,
        ssl_result: SSLAnalysisResult,
        whois_result: WHOISAnalysisResult,
        header_result: HeaderAnalysisResult,
        redirect_result: RedirectAnalysisResult,
    ) -> AIThreatAnalysisResult:
        """
        Produces an AIThreatAnalysisResult. Uses the configured AI provider when enabled;
        otherwise returns deterministic fallback.
        """
        evidence = self._build_evidence(
            trust_evaluation, ssl_result, whois_result,
            header_result, redirect_result
        )

        if self._is_ai_enabled():
            try:
                provider = self._providers.get(settings.AI_THREAT_ANALYSIS_PROVIDER)
                if provider is None:
                    logger.warning(
                        f"Unknown AI threat provider '{settings.AI_THREAT_ANALYSIS_PROVIDER}', "
                        "using deterministic fallback."
                    )
                    return self._get_fallback(trust_evaluation)

                return await provider.analyze_threat(
                    model=settings.AI_THREAT_ANALYSIS_MODEL,
                    api_key=settings.AI_THREAT_ANALYSIS_API_KEY or "",
                    evidence=evidence,
                )
            except Exception as exc:
                logger.warning(
                    f"AI threat analysis provider failed: {exc}. "
                    "Returning deterministic fallback."
                )
                return self._get_fallback(trust_evaluation)

        return self._get_fallback(trust_evaluation)

    # ------------------------------------------------------------------
    # Evidence Builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_evidence(
        trust_evaluation: TrustEvaluationResult,
        ssl_result: SSLAnalysisResult,
        whois_result: WHOISAnalysisResult,
        header_result: HeaderAnalysisResult,
        redirect_result: RedirectAnalysisResult,
    ) -> Dict[str, Any]:
        return {
            "trust_score": trust_evaluation.trust_score,
            "risk_level": trust_evaluation.risk_level.value,
            "reasons": trust_evaluation.reasons,
            "ssl": {
                "is_valid": ssl_result.is_valid,
                "error": ssl_result.error,
            },
            "whois": {
                "is_registered": whois_result.is_registered,
                "domain_age_days": whois_result.domain_age_days,
            },
            "headers": {
                "security_headers_score": header_result.security_headers_score,
                "missing_headers": header_result.missing_headers,
            },
            "redirect": {
                "redirect_count": redirect_result.redirect_count,
                "cross_domain_redirect": redirect_result.cross_domain_redirect,
                "https_upgrade": redirect_result.https_upgrade,
            },
        }

    # ------------------------------------------------------------------
    # Feature Gate
    # ------------------------------------------------------------------

    @staticmethod
    def _is_ai_enabled() -> bool:
        return (
            settings.AI_THREAT_ANALYSIS_ENABLED
            and bool(settings.AI_THREAT_ANALYSIS_API_KEY)
            and bool(settings.AI_THREAT_ANALYSIS_MODEL)
        )

    # ------------------------------------------------------------------
    # Deterministic Fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _get_fallback(trust_evaluation: TrustEvaluationResult) -> AIThreatAnalysisResult:
        suspicious_indicators = [
            reason for reason in trust_evaluation.reasons if ": -" in reason
        ]
        return AIThreatAnalysisResult(
            enabled=False,
            threat_level="UNKNOWN",
            confidence=0.0,
            suspicious_indicators=suspicious_indicators,
            reasoning="AI threat analysis is disabled.",
            recommended_action="Follow deterministic trust assessment recommendation."
        )
