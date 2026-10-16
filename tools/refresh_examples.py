"""Explicit maintainer tool: refresh original synthetic fixtures and golden files.

Run from the checkout root: python tools/refresh_examples.py
Tests only READ goldens; they never regenerate expected output.
"""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from infra_policy_checker.analysis import analyze
from infra_policy_checker.reporters import render
from tests.support import FIXTURES, GOLDENS, synthetic_fixtures


def main():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    GOLDENS.mkdir(parents=True, exist_ok=True)
    for name, value in synthetic_fixtures().items():
        (FIXTURES / (name + ".json")).write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    for name in ("safe", "unsafe", "mixed", "computed", "marked-sensitive", "nested",
                 "no-change", "delete-only"):
        report = analyze(synthetic_fixtures()[name])
        for format_name in ("text", "json", "sarif"):
            (GOLDENS / (name + "." + format_name)).write_text(
                render(report, format_name), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
