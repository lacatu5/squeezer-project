"""DAST scanner module.

This package contains the core template execution engine for DAST scanning.
"""

from dast.scanner.context import ExecutionContext
from dast.scanner.engine import TemplateEngine, load_templates, run_scan

__all__ = [
    "ExecutionContext",
    "TemplateEngine",
    "load_templates",
    "run_scan",
]
