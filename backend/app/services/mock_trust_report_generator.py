import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

from app.models.enums import RiskLevel


class MockTrustReportGenerator:
    """
    Mock generator that simulates the future trust intelligence engine.
    It calculates a deterministic trust score based on the URL hash.
    """
    def generate(self, url: str) -> Dict[str, Any]:
        """
        Generate a deterministic mock trust report for the given URL.
        """
        # Normalize URL to ensure deterministic hashing
        normalized_url = url.strip().lower()

        # Compute SHA-256 hash of the normalized URL string
        hash_object = hashlib.sha256(normalized_url.encode("utf-8"))
        hash_hex = hash_object.hexdigest()

        # Take the first 8 characters (32 bits) of the hex digest and convert to integer
        seed_value = int(hash_hex[:8], 16)

        # Map to a deterministic trust score between 0 and 100
        trust_score = seed_value % 101

        # Classify risk level based on the trust score boundaries
        if trust_score >= 80:
            risk_level = RiskLevel.LOW
            summary = "Website appears trustworthy based on the mock analysis."
        elif trust_score >= 50:
            risk_level = RiskLevel.MEDIUM
            summary = "Website shows moderate trust indicators."
        else:
            risk_level = RiskLevel.HIGH
            summary = "Website may present elevated security risks."

        return {
            "trust_score": trust_score,
            "risk_level": risk_level,
            "summary": summary,
            "generated_at": datetime.now(timezone.utc)
        }
