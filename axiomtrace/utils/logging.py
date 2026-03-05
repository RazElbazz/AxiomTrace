"""Logging configuration for AxiomTrace."""

import logging
import sys


def setup_logging(level: int = logging.INFO) -> None:
    """Configure root logger for AxiomTrace."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root = logging.getLogger("axiomtrace")
    root.setLevel(level)
    root.addHandler(handler)
