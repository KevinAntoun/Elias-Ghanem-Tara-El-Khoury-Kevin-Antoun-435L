"""Sphinx configuration for team-written Python docstrings."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
project = "Security Incident Detection and Response Management System"
author = "Sprint 1 project team"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.napoleon"]
templates_path = []
exclude_patterns = ["_build"]
html_theme = "alabaster"
