# AxiomTrace

Forensic system integrity verification framework. AxiomTrace collects, parses, and validates system and application artifacts to produce structured integrity reports.

## Architecture

```
axiomtrace/
├── collectors/            # Data acquisition layer
│   ├── base.py            # BaseCollector ABC, SystemCollector, SpecializedCollector
│   ├── system/            # OS-level collectors
│   │   ├── usn_journal.py # NTFS USN Journal reader
│   │   ├── prefetch.py    # Windows Prefetch parser
│   │   ├── memory.py      # Process memory inspector
│   │   └── disk.py        # Disk / MFT artifact collector
│   └── specialized/       # Application-specific collectors
│       └── minecraft/
│           ├── mod_scanner.py       # Mod directory fingerprinting
│           ├── macro_detector.py    # Macro / auto-clicker detection
│           └── process_inspector.py # JVM process memory inspection
├── parsers/               # Analysis logic layer
│   ├── base.py            # BaseParser ABC, ValidationResult
│   ├── system/            # System artifact parsers
│   └── specialized/
│       └── minecraft/     # Minecraft artifact parsers
├── signatures/            # Data layer (rules & patterns)
│   ├── base.py            # Signature data model
│   ├── system/            # System-level signatures
│   └── specialized/
│       └── minecraft/     # Minecraft-specific signatures
├── core/
│   └── engine.py          # AxiomEngine orchestrator
├── output/
│   └── report.py          # Report formatters (JSON, dict)
└── utils/
    └── logging.py         # Logging configuration
```

### Design Principles

- **Modular Collector System** - All collectors inherit from `BaseCollector` (ABC). System collectors extend `SystemCollector`; application-specific collectors extend `SpecializedCollector`.
- **Separation of Concerns** - Parsers contain analysis *logic*. Signatures contain *data* (rules, hashes, patterns). Collectors handle *acquisition*.
- **Pipeline Architecture** - `AxiomEngine` runs collectors, feeds artifacts to parsers, and aggregates results into a `ScanReport`.

## Getting Started

```bash
# Install in development mode
pip install -e ".[dev]"

# Run (once collectors are implemented)
python -m axiomtrace
```

## Requirements

- Python 3.12+
- Windows (for system-level collectors: USN Journal, Prefetch, Memory)

## Project Status

Initial scaffolding. Collector implementations are stubbed with `NotImplementedError` - ready for incremental development.

## License

Proprietary - All rights reserved.