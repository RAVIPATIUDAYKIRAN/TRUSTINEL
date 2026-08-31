import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Set

from app.analyzers.base_analyzer import BaseAnalyzer
from app.schemas.website_fetch import WebsiteFetchResult
from app.schemas.phishing import (
    PhishingImpersonationResult,
    ImpersonationConfidence,
    PhishingDetectionType,
)

logger = logging.getLogger("trustinel.analyzers.phishing")

# Controlled high-confidence static registry of protected brands and canonical domains
BRAND_REGISTRY: Dict[str, str] = {
    "paypal": "paypal.com",
    "google": "google.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "twitter": "twitter.com",
    "trustinel": "trustinel.io",
}

# Homoglyph translation mapping Cyrillic/Greek/Lookalike characters to ASCII
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'α': 'a', 'е': 'e', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q',
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '@': 'a', '$': 's'
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "auth", "account", "support", "billing", "portal", "helpdesk"
}


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance (insertions, deletions, substitutions, transpositions)."""
    d: Dict[Tuple[int, int], int] = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost) # transposition
    return d[(len1 - 1, len2 - 1)]


def normalize_homoglyphs(text: str) -> str:
    """Translates look-alike homoglyph characters to standard ASCII equivalent."""
    res = []
    for char in text:
        res.append(HOMOGLYPH_MAP.get(char.lower(), char.lower()))
    return "".join(res)


def decode_punycode_label(label: str) -> str:
    """Safely decodes Punycode xn-- labels to Unicode if present."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            return label
    return label


class PhishingAnalyzer(BaseAnalyzer):
    """
    Analyzer evaluating domain typosquatting, character manipulations,
    homoglyphs/IDN abuse, subdomain brand impersonation, and keyword tricks.
    """

    async def analyze(self, fetch_result: WebsiteFetchResult) -> PhishingImpersonationResult:
        domain = fetch_result.domain or fetch_result.url
        return await self.analyze_domain(domain)

    async def analyze_domain(self, raw_domain: str) -> PhishingImpersonationResult:
        if not raw_domain or not isinstance(raw_domain, str):
            clean_domain = ""
        else:
            clean_domain = raw_domain.strip().lower().rstrip(".")

        # Input bounds check to prevent CPU exhaustion on oversized inputs
        if len(clean_domain) > 253:
            clean_domain = clean_domain[:253]

        if not clean_domain or "." not in clean_domain:
            return PhishingImpersonationResult(
                input_domain=raw_domain,
                normalized_domain=clean_domain,
                is_impersonation_suspected=False,
                confidence_level=ImpersonationConfidence.NONE,
                security_findings=["Invalid domain structure for phishing analysis."]
            )

        parts = clean_domain.split(".")
        sld = parts[-2] if len(parts) >= 2 else parts[0]
        tld = parts[-1]

        # 1. Exact match for legitimate brand canonical domains or official subdomains
        for brand_name, canonical_domain in BRAND_REGISTRY.items():
            if clean_domain == canonical_domain or clean_domain.endswith("." + canonical_domain):
                return PhishingImpersonationResult(
                    input_domain=raw_domain,
                    normalized_domain=clean_domain,
                    is_impersonation_suspected=False,
                    suspected_brand=brand_name.capitalize(),
                    matched_legitimate_domain=canonical_domain,
                    similarity_score=1.0,
                    confidence_level=ImpersonationConfidence.NONE,
                    security_findings=["Domain is an official legitimate brand destination."]
                )

        detection_types: Set[PhishingDetectionType] = set()
        findings: List[str] = []
        best_brand: Optional[str] = None
        best_canonical: Optional[str] = None
        highest_similarity = 0.0
        confidence = ImpersonationConfidence.NONE

        # 2. Decode Punycode / Homoglyph check
        decoded_parts = [decode_punycode_label(p) for p in parts]
        decoded_domain = ".".join(decoded_parts)
        ascii_normalized_domain = normalize_homoglyphs(decoded_domain)

        is_punycode = any(p.startswith("xn--") for p in parts)
        has_homoglyphs = (ascii_normalized_domain != clean_domain)

        # 3. Subdomain Impersonation Check (e.g. paypal.com.attacker.net)
        subdomains = parts[:-2] if len(parts) > 2 else []
        for brand_name, canonical_domain in BRAND_REGISTRY.items():
            # Check if canonical domain or brand string is present in subdomains
            for sub in subdomains:
                if brand_name in sub or canonical_domain in sub:
                    detection_types.add(PhishingDetectionType.SUBDOMAIN_IMPERSONATION)
                    best_brand = brand_name.capitalize()
                    best_canonical = canonical_domain
                    highest_similarity = 0.95
                    confidence = ImpersonationConfidence.HIGH
                    findings.append(f"Subdomain impersonation detected: Subdomain '{sub}' contains protected brand '{brand_name}'.")

        # 4. Brand Keyword Combination Check (e.g. apple-login-security.com)
        clean_sld_hyphen_parts = sld.split("-")
        for brand_name, canonical_domain in BRAND_REGISTRY.items():
            if brand_name in clean_sld_hyphen_parts or (brand_name in sld and len(sld) > len(brand_name)):
                # Check if combined with phishing keywords
                has_keyword = any(kw in sld for kw in PHISHING_KEYWORDS)
                if has_keyword or "-" in sld:
                    detection_types.add(PhishingDetectionType.BRAND_KEYWORD_INCLUSION)
                    if "-" in sld:
                        detection_types.add(PhishingDetectionType.HYPHENATION_TRICK)
                    if not best_brand:
                        best_brand = brand_name.capitalize()
                        best_canonical = canonical_domain
                        highest_similarity = max(highest_similarity, 0.88)
                        confidence = ImpersonationConfidence.HIGH
                    findings.append(f"Deceptive brand keyword inclusion: SLD '{sld}' combines protected brand '{brand_name}' with hyphens or security keywords.")

        # 5. Algorithmic Typosquatting Analysis (omission, insertion, substitution, transposition, repeated chars)
        homoglyph_sld = normalize_homoglyphs(decode_punycode_label(sld))

        for brand_name, canonical_domain in BRAND_REGISTRY.items():
            brand_sld = canonical_domain.split(".")[0]
            dist = damerau_levenshtein_distance(homoglyph_sld, brand_sld)

            # Handle homoglyph/Punycode spoofing when normalized homoglyph matches brand
            if dist == 0:
                if has_homoglyphs or is_punycode:
                    detection_types.add(PhishingDetectionType.HOMOGLYPH_IDN_ABUSE)
                    best_brand = brand_name.capitalize()
                    best_canonical = canonical_domain
                    highest_similarity = 1.0
                    confidence = ImpersonationConfidence.HIGH
                    findings.append(f"Homoglyph / Punycode (IDN) spoofing attack: '{clean_domain}' visually spoofs '{canonical_domain}'.")
                continue

            max_len = max(len(homoglyph_sld), len(brand_sld))
            similarity = round(1.0 - (dist / max_len), 2)

            if dist <= 2 or similarity >= 0.70:
                if similarity > highest_similarity:
                    highest_similarity = similarity
                    best_brand = brand_name.capitalize()
                    best_canonical = canonical_domain

                # Classify specific typosquatting technique
                len_diff = len(homoglyph_sld) - len(brand_sld)
                if dist == 1:
                    confidence = ImpersonationConfidence.HIGH
                    if len_diff == -1:
                        detection_types.add(PhishingDetectionType.TYPOSQUATTING_OMISSION)
                        findings.append(f"Typosquatting (omission): '{sld}' missing 1 character compared to '{brand_sld}'.")
                    elif len_diff == 1:
                        # Check repeated character
                        has_repeat = any(c * 2 in homoglyph_sld and c * 2 not in brand_sld for c in homoglyph_sld)
                        if has_repeat:
                            detection_types.add(PhishingDetectionType.REPEATED_CHARACTER)
                            findings.append(f"Repeated character attack: '{sld}' contains duplicated characters targeting '{brand_sld}'.")
                        else:
                            detection_types.add(PhishingDetectionType.TYPOSQUATTING_INSERTION)
                            findings.append(f"Typosquatting (insertion): '{sld}' contains 1 extra character compared to '{brand_sld}'.")
                    elif len_diff == 0:
                        # Check transposition vs substitution
                        is_transposition = False
                        for i in range(len(homoglyph_sld) - 1):
                            swapped = list(homoglyph_sld)
                            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
                            if "".join(swapped) == brand_sld:
                                is_transposition = True
                                break
                        if is_transposition:
                            detection_types.add(PhishingDetectionType.TYPOSQUATTING_TRANSPOSITION)
                            findings.append(f"Typosquatting (transposition): Swapped adjacent characters in '{sld}' targeting '{brand_sld}'.")
                        else:
                            detection_types.add(PhishingDetectionType.TYPOSQUATTING_SUBSTITUTION)
                            findings.append(f"Typosquatting (substitution): Substituted character in '{sld}' targeting '{brand_sld}'.")
                elif dist == 2:
                    if similarity >= 0.75:
                        confidence = max(confidence, ImpersonationConfidence.MEDIUM, key=lambda c: c.value)
                        detection_types.add(PhishingDetectionType.TYPOSQUATTING_SUBSTITUTION)
                        findings.append(f"High similarity typosquatting: '{sld}' is {int(similarity * 100)}% similar to '{brand_sld}'.")

        # Add homoglyph / Punycode finding if detected in combination with suspicious similarity
        if (is_punycode or has_homoglyphs) and (best_brand or highest_similarity >= 0.70):
            detection_types.add(PhishingDetectionType.HOMOGLYPH_IDN_ABUSE)
            confidence = ImpersonationConfidence.HIGH
            findings.append("Homoglyph / Punycode (IDN) abuse: Domain uses look-alike characters or Punycode to spoof a protected brand.")

        is_suspected = len(detection_types) > 0 and confidence in (ImpersonationConfidence.HIGH, ImpersonationConfidence.MEDIUM)

        return PhishingImpersonationResult(
            input_domain=raw_domain,
            normalized_domain=clean_domain,
            is_impersonation_suspected=is_suspected,
            suspected_brand=best_brand if is_suspected else None,
            matched_legitimate_domain=best_canonical if is_suspected else None,
            similarity_score=highest_similarity if is_suspected else 0.0,
            confidence_level=confidence if is_suspected else ImpersonationConfidence.NONE,
            detection_types=list(detection_types) if is_suspected else [],
            security_findings=findings if is_suspected else ["No brand impersonation or typosquatting indicators detected."],
            checked_at=datetime.now(timezone.utc)
        )
