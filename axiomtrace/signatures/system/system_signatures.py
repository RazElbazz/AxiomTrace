"""System-level validation signatures.

Contains signatures for detecting common system-level integrity
anomalies such as timestamp manipulation tools, anti-forensic
utilities, and process injection frameworks.
"""

from __future__ import annotations

from axiomtrace.signatures.base import Signature, SignatureType

SYSTEM_SIGNATURES: list[Signature] = [
    # Example signatures - expand as needed
    Signature(
        id="SYS-001",
        name="Timestamp Manipulation Utility",
        description="Known file-timestamp modification tool detected in execution history",
        signature_type=SignatureType.FILE_NAME,
        pattern="timestomp",
        severity="high",
        tags=("anti-forensic", "timestamp"),
    ),
]
