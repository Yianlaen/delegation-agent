"""Portable locations for the selected experiment workspace."""

import json
from pathlib import Path


def location(root, key, default):
    root = Path(root).resolve()
    config_path = root / "config/study.json"
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    return (root / config.get(key, default)).resolve()


def data_root(root):
    return location(root, "data_directory", "data")


def results_root(root):
    return location(root, "results_directory", "results")


def reports_root(root):
    return location(root, "reports_directory", "reports")
