"""Base definitions for the signature / rule data layer.

Signatures are pure data: they describe *what* to look for.
Parsers contain the *logic* for how to match them against collected artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SignatureType(Enum):
    """Category of signature match."""

    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    BYTE_PATTERN = "byte_pattern"
    PROCESS_NAME = "process_name"
    REGISTRY_KEY = "registry_key"
    BEHAVIORAL = "behavioral"


@dataclass(frozen=True)
class Signature:
    """A single validation rule definition."""

    id: str
    name: str
    description: str
    signature_type: SignatureType
    pattern: str | bytes
    severity: str = "medium"
    tags: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict = field(default_factory=dict)
