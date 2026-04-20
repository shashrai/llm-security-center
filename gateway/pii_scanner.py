"""
Author:Shashankitrai@gmail.com
PII Scanner — detects and tokenises sensitive entities in prompt text.

Uses a layered approach:
  1. High-performance regex patterns (structured PII — SSN, card numbers, etc.)
  2. NLP-based Named Entity Recognition via spaCy (unstructured PII — names, addresses)
  3. Financial domain patterns (account numbers, IBAN, routing numbers)

Design principle: logs entity TYPE, never entity VALUE — data minimisation.
Detected entities are replaced with typed tokens: <REDACTED:SSN>, <REDACTED:PERSON>, etc.
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ── Regex pattern library ─────────────────────────────────────────────────────
# Each pattern: (entity_type, regex, confidence_score)
REGEX_PATTERNS = [
    # US Social Security Number
    ("SSN", r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b", 0.95),
    # Credit / debit card numbers (Luhn-valid patterns)
    ("CREDIT_CARD", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b", 0.95),
    # Card numbers with spaces/dashes (common user input)
    ("CREDIT_CARD", r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b", 0.90),
    # US phone numbers
    ("PHONE_NUMBER", r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b", 0.85),
    # Email addresses
    ("EMAIL_ADDRESS", r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", 0.95),
    # US bank routing numbers (9 digits, ABA format)
    ("BANK_ROUTING", r"\b(?:0[0-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|8[0])\d{7}\b", 0.80),
    # IBAN
    ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b", 0.90),
    # US passport numbers
    ("PASSPORT", r"\b[A-Z]{1,2}\d{6,9}\b", 0.70),
    # Date of birth patterns
    ("DATE_OF_BIRTH", r"\b(?:dob|date of birth|born on|born)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", 0.85),
    # IPv4 addresses (privacy-relevant in logs)
    ("IP_ADDRESS", r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", 0.80),
    # AWS Access Key IDs
    ("API_KEY", r"\bAKIA[0-9A-Z]{16}\b", 0.99),
    # Generic API keys / secrets (high entropy strings prefixed with common patterns)
    ("API_KEY", r"\b(?:sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}\b", 0.90),
    # US Driver License (common formats)
    ("DRIVER_LICENSE", r"\b[A-Z]\d{7}\b|\b\d{9}\b", 0.60),  # lower confidence — overlaps with other patterns
]

# NLP entity types from spaCy to treat as PII
NLP_PII_TYPES = {"PERSON", "GPE", "LOC", "ORG", "FAC"}
NLP_CONFIDENCE = 0.75

# Minimum confidence to redact
REDACT_THRESHOLD = 0.70


@dataclass
class Detection:
    entity_type: str
    start: int
    end: int
    score: float
    original_text: str  # only used internally — never logged externally


class PIIScanner:
    def __init__(self, use_nlp: bool = True):
        self.use_nlp = use_nlp
        self.nlp = None
        self._load_nlp()

    def _load_nlp(self):
        if not self.use_nlp:
            return
        try:
            import spacy
            try:
                self.nlp = spacy.load("en_core_web_sm")
                logger.info("✅ spaCy NLP model loaded")
            except OSError:
                logger.warning(
                    "spaCy model 'en_core_web_sm' not found. "
                    "Run: python -m spacy download en_core_web_sm\n"
                    "Falling back to regex-only PII detection."
                )
                self.use_nlp = False
        except ImportError:
            logger.warning("spaCy not installed. Using regex-only PII detection.")
            self.use_nlp = False

    def _regex_scan(self, text: str) -> list[Detection]:
        detections = []
        for entity_type, pattern, score in REGEX_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                if score >= REDACT_THRESHOLD:
                    detections.append(Detection(
                        entity_type=entity_type,
                        start=match.start(),
                        end=match.end(),
                        score=score,
                        original_text=match.group(),
                    ))
        return detections

    def _nlp_scan(self, text: str) -> list[Detection]:
        if not self.nlp:
            return []
        detections = []
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.label_ in NLP_PII_TYPES:
                detections.append(Detection(
                    entity_type=ent.label_,
                    start=ent.start_char,
                    end=ent.end_char,
                    score=NLP_CONFIDENCE,
                    original_text=ent.text,
                ))
        return detections

    def _merge_detections(self, detections: list[Detection]) -> list[Detection]:
        """Remove overlapping detections, preferring higher-confidence ones."""
        if not detections:
            return []
        sorted_d = sorted(detections, key=lambda d: (d.start, -d.score))
        merged = [sorted_d[0]]
        for det in sorted_d[1:]:
            last = merged[-1]
            # If this detection starts after the last one ends, include it
            if det.start >= last.end:
                merged.append(det)
            # If it overlaps but has higher confidence, replace
            elif det.score > last.score:
                merged[-1] = det
        return merged

    def scan_and_sanitise(self, text: str) -> dict:
        """
        Scan text for PII and return sanitised version.

        Returns:
            {
                "sanitised_text": str,        # text with PII replaced by tokens
                "detections": [               # audit-safe detection list (no values)
                    {"entity_type": str, "score": float}
                ]
            }
        """
        regex_dets = self._regex_scan(text)
        nlp_dets = self._nlp_scan(text)
        all_dets = self._merge_detections(regex_dets + nlp_dets)

        if not all_dets:
            return {"sanitised_text": text, "detections": []}

        # Build sanitised text by replacing from right to left (preserves indices)
        sanitised = text
        for det in sorted(all_dets, key=lambda d: d.start, reverse=True):
            token = f"<REDACTED:{det.entity_type}>"
            sanitised = sanitised[:det.start] + token + sanitised[det.end:]

        # Return audit-safe detections (entity type + score only — NO values)
        audit_detections = [
            {"entity_type": d.entity_type, "score": round(d.score, 2)}
            for d in all_dets
        ]

        return {
            "sanitised_text": sanitised,
            "detections": audit_detections,
        }

    def scan_only(self, text: str) -> list[dict]:
        """Scan without sanitising — returns detection metadata only."""
        regex_dets = self._regex_scan(text)
        nlp_dets = self._nlp_scan(text)
        merged = self._merge_detections(regex_dets + nlp_dets)
        return [{"entity_type": d.entity_type, "score": d.score} for d in merged]
