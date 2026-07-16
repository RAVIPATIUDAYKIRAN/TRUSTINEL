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
