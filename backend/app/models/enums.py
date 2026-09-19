from enum import Enum


class ScanStatus(str, Enum):
    """
    Status lifecycle of a website scan.
    """
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RiskLevel(str, Enum):
    """
    Risk severity classification of a scanned website.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class UserFacingVerdict(str, Enum):
    """
    User-facing trust verdict classification.
    """
    LEGITIMATE = "LEGITIMATE"
    PROBABLY_LEGITIMATE = "PROBABLY_LEGITIMATE"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_SCAM = "LIKELY_SCAM"
    HIGH_CONFIDENCE_SCAM = "HIGH_CONFIDENCE_SCAM"
    UNKNOWN = "UNKNOWN"

