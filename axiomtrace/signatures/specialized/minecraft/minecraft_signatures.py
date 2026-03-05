"""Minecraft-specific validation signatures.

Contains file hashes, process names, byte patterns, and behavioral
indicators for known cheat clients, macro tools, and injection
frameworks targeting Minecraft: Java Edition.
"""

from axiomtrace.signatures.base import Signature, SignatureType

MINECRAFT_MOD_SIGNATURES: list[Signature] = [
    # Example signatures - expand with real data
    Signature(
        id="MC-MOD-001",
        name="Unauthorized Client Module",
        description="Known unauthorized game client modification detected in mods directory",
        signature_type=SignatureType.FILE_NAME,
        pattern="*-client.jar",
        severity="critical",
        tags=("mod", "client-modification"),
    ),
]

MINECRAFT_MACRO_SIGNATURES: list[Signature] = [
    Signature(
        id="MC-MACRO-001",
        name="Input Automation Software",
        description="Known macro / auto-clicker process detected",
        signature_type=SignatureType.PROCESS_NAME,
        pattern="autoclicker",
        severity="high",
        tags=("macro", "automation"),
    ),
]

MINECRAFT_INJECTION_SIGNATURES: list[Signature] = [
    Signature(
        id="MC-INJ-001",
        name="JVM Agent Injection",
        description="Suspicious Java agent loaded into Minecraft process",
        signature_type=SignatureType.BEHAVIORAL,
        pattern="-javaagent:",
        severity="critical",
        tags=("injection", "jvm-agent"),
    ),
]
