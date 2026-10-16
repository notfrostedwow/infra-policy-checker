"""Hash tracked worktree files, excluding manifest and verification metadata.

Use after staging the intended file list. No archive or real-plan export.
"""

import argparse
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {"MANIFEST.sha256", "docs/verification.md"}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode("utf-8").split("\0")
    entries = []
    for name in sorted(n for n in names if n and n not in EXCLUDED):
        path = ROOT / name
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise SystemExit("Manifest requires regular tracked files inside checkout.")
        entries.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + name)
    content = "\n".join(entries) + "\n"
    manifest = ROOT / "MANIFEST.sha256"
    if args.write:
        manifest.write_text(content, encoding="utf-8", newline="\n")
    elif manifest.read_text(encoding="utf-8") != content:
        raise SystemExit("Manifest differs from tracked worktree content.")
    print(f"SHA256 manifest: {len(entries)} files; excludes manifest and verification metadata.")


if __name__ == "__main__":
    main()
