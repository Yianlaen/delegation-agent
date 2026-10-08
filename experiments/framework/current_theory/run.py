#!/usr/bin/env python3
"""Run from any working directory, with no install or package download."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from authorization_experiment.cli import main

if __name__ == "__main__":
    main(default_root=ROOT)
