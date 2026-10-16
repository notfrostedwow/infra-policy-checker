"""Assert offline CLI statuses and verify generated README excerpts."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COUNT = 0


def run(arguments, expected, data=None):
    global COUNT
    result = subprocess.run([sys.executable, "-m", "infra_policy_checker", *arguments],
                            cwd=ROOT, input=data, capture_output=True, timeout=15)
    if result.returncode != expected:
        raise SystemExit("Smoke command returned an unexpected status.")
    if expected != 2 and result.stderr:
        raise SystemExit("Smoke command emitted unexpected diagnostics.")
    COUNT += 1
    return result.stdout.decode("utf-8").replace("\r\n", "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-excerpts", action="store_true")
    args = parser.parse_args()
    for arguments in (["--help"], ["--version"], ["scan", "--help"], ["rules"],
                      ["rules", "--format", "json"]):
        run(arguments, 0)
    safe = run(["scan", "tests/fixtures/safe.json"], 0)
    unsafe = run(["scan", "tests/fixtures/unsafe.json", "--format", "json"], 1)
    computed = run(["scan", "tests/fixtures/computed.json", "--format", "sarif"], 3)
    run(["scan", "tests/fixtures/malformed.json"], 2)
    run(["scan", "tests/fixtures/mixed.json", "--fail-on", "high"], 3)
    run(["scan", "tests/fixtures/no-change.json"], 3)
    raw = (ROOT / "tests/fixtures/safe.json").read_bytes()
    run(["scan", "-", "--max-input-bytes", str(len(raw))], 0, raw)
    run(["scan", "-", "--max-input-bytes", str(len(raw) - 1)], 2, raw)
    with tempfile.TemporaryDirectory(prefix=".ipc-test-", dir=ROOT) as temporary:
        path = Path(temporary) / "report.json"
        text = run(["scan", "tests/fixtures/safe.json", "--format", "json",
                    "--output", str(path)], 0)
        if json.loads(path.read_bytes()) != json.loads(text):
            raise SystemExit("Saved report differs from stdout.")
    counts = json.dumps(json.loads(unsafe)["coverage"]["outcomes"], sort_keys=True)
    sarif_exit = json.loads(computed)["runs"][0]["properties"]["exitCode"]
    excerpt = ("\nText from safe.json:\n\n~~~text\n"
               + "\n".join(safe.splitlines()[:3] + safe.splitlines()[-2:]) + "\n~~~\n"
               + "\nJSON outcome counts from unsafe.json:\n\n~~~json\n"
               + counts + "\n~~~\n"
               + f"\nSARIF from computed.json: version 2.1.0; exitCode {sarif_exit}; "
               + "six UNKNOWN results, logical locations only.\n\n")
    readme = ROOT / "README.md"
    start, end = "<!-- GENERATED-EXCERPTS-START -->", "<!-- GENERATED-EXCERPTS-END -->"
    prefix, rest = readme.read_text(encoding="utf-8").split(start)
    old, suffix = rest.split(end)
    if args.write_excerpts:
        readme.write_text(prefix + start + excerpt + end + suffix, encoding="utf-8", newline="\n")
    elif old != excerpt:
        raise SystemExit("README excerpts differ from generated synthetic output.")
    print(f"{COUNT} offline smoke commands passed; README excerpts match.")


if __name__ == "__main__":
    main()
