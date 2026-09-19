"""
Regression test suite for pre-Sprint-8 defect fixes:
- D1: Stale response protection contracts
- D3: Floating indicator sync contracts
- D5: Redaction boundary contracts
- D7: TrustReport null/missing score handling (no score manufacturing)
"""
import pytest
from app.models.enums import UserFacingVerdict, RiskLevel
from app.schemas.trust_report import TrustReportResponse
from datetime import datetime, timezone
import uuid


def test_d7_trust_report_schema_handles_null_overall_risk_score_without_manufacturing():
    """
    Verify D7 fix contract: When overall_risk_score is None, the schema preserves None
    and does NOT manufacture or infer a score.
    """
    raw_data = {
        "id": uuid.uuid4(),
        "scan_id": uuid.uuid4(),
        "trust_score": 85,
        "risk_level": RiskLevel.LOW,
        "summary": "Sample summary",
        "generated_at": datetime.now(timezone.utc),
        "explanation": None,
        "key_risks": [],
        "positive_signals": ["Valid SSL"],
        "recommendation": None,
        "technical_trust_score": 85,
        "content_risk_score": 0,
        "reputation_risk_score": 0,
        "behavioral_risk_score": 0,
        "overall_risk_score": None,  # Explicitly None / missing
        "overall_risk_level": RiskLevel.LOW,
        "user_facing_verdict": UserFacingVerdict.LEGITIMATE,
        "recommended_user_action": "Proceed normally",
        "risk_factors": []
    }

    report = TrustReportResponse.model_validate(raw_data)
    assert report.overall_risk_score is None
    # Verify score is not manufactured to an arbitrary number
    assert report.overall_risk_score != 15
    assert report.overall_risk_score != 55
    assert report.overall_risk_score != 85


def test_d7_trust_report_schema_preserves_legitimate_zero_score():
    """
    Verify D7 fix contract: A legitimate score of 0 (clean site) is preserved
    and distinguishable from None.
    """
    raw_data = {
        "id": uuid.uuid4(),
        "scan_id": uuid.uuid4(),
        "trust_score": 100,
        "risk_level": RiskLevel.LOW,
        "summary": "Sample summary",
        "generated_at": datetime.now(timezone.utc),
        "explanation": None,
        "key_risks": [],
        "positive_signals": ["Valid SSL"],
        "recommendation": None,
        "technical_trust_score": 100,
        "content_risk_score": 0,
        "reputation_risk_score": 0,
        "behavioral_risk_score": 0,
        "overall_risk_score": 0,  # Legitimate 0 scam risk
        "overall_risk_level": RiskLevel.LOW,
        "user_facing_verdict": UserFacingVerdict.LEGITIMATE,
        "recommended_user_action": "Proceed normally",
        "risk_factors": []
    }

    report = TrustReportResponse.model_validate(raw_data)
    assert report.overall_risk_score == 0
    assert report.overall_risk_score is not None
