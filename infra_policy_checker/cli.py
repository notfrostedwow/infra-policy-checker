"""CLI boundary: explicit local reads, safe diagnostics and atomic report writes."""

import argparse
import errno
import os
from pathlib import Path
import stat
import sys
import tempfile

from . import __version__
from .analysis import analyze
from .inputs import DEFAULT_LIMIT, HARD_LIMIT, InputError, read_input, require
from .reporters import json_text, render
from .rules import RULES


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's usual error embeds unknown arguments and their values.
        raise InputError("Invalid command arguments; use --help.")


def parser():
    result = SafeParser(prog="infra-policy-checker", description=(
        "Offline bounded review of selected planned AWS settings. Input: UTF-8 "
        "terraform show -json of an existing saved plan; never an event stream or state."))
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    rules = commands.add_parser("rules", help="List six supported local policies")
    rules.add_argument("--format", choices=("text", "json"), default="text")
    scan = commands.add_parser("scan", help="Read one saved-plan JSON file, or '-' for bounded stdin")
    scan.add_argument("input", help="Explicit regular JSON file path or '-'")
    scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan.add_argument("--fail-on", choices=("medium", "high"), default="medium",
                      help="Failure threshold (default: medium); uncertainty remains visible")
    scan.add_argument("--max-input-bytes", type=int, default=DEFAULT_LIMIT,
                      help=f"Byte limit, default {DEFAULT_LIMIT}, hard cap {HARD_LIMIT}")
    scan.add_argument("--output", help="Atomically save report; stdout still contains the report")
    return result


def output_target(path, input_path):
    target = Path(path)
    # Reject parent symlinks/reparse points too. This is a best-effort path check;
    # portable Python cannot close every adversarial directory-substitution race.
    for component in (target.absolute(), *target.absolute().parents):
        if component.exists() or component.is_symlink():
            info = component.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not (getattr(info, "st_file_attributes", 0) & 0x400),
                    "Output path must not contain symlinks or reparse points.")
    if target.exists():
        require(stat.S_ISREG(target.lstat().st_mode), "Output must be a regular file.")
    if input_path != "-":
        source = Path(input_path)
        require(target.resolve() != source.resolve(), "Output cannot overwrite input.")
        if target.exists():
            require(not os.path.samefile(target, source), "Output cannot overwrite input.")
    return target


def atomic_write(target, content, input_path):
    # Serialize/validate before this function. Temp in the same directory keeps
    # os.replace atomic on normal local filesystems. Recheck the target first.
    fd, temporary = tempfile.mkstemp(prefix=".infra-policy-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if hasattr(os, "fchmod"):
                os.fchmod(stream.fileno(), 0o600)
            stream.write(content.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        output_target(target, input_path)
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        if args.command == "rules":
            items = [{"id": r.id, "severity": r.severity, "title": r.title} for r in RULES]
            content = json_text(items) if args.format == "json" else "\n".join(
                f"{r['id']} [{r['severity']}] {r['title']}" for r in items) + "\n"
            exit_code = 0
        else:
            require(1 <= args.max_input_bytes <= HARD_LIMIT, "Invalid input byte limit.")
            target = output_target(args.output, args.input) if args.output else None
            plan = read_input(args.input, sys.stdin.buffer, args.max_input_bytes)
            report = analyze(plan, args.fail_on)
            content = render(report, args.format)
            exit_code = report["exit_code"]
            # An errored Terraform plan still has a reviewable stdout report,
            # but a failed analysis must preserve a prior report on disk.
            if target is not None and exit_code != 2:
                atomic_write(target, content, args.input)
        try:
            sys.stdout.write(content)
            sys.stdout.flush()
        except OSError as error:
            windows_closed_pipe = (
                os.name == "nt" and error.errno == errno.EINVAL
                and stat.S_ISFIFO(os.fstat(sys.stdout.fileno()).st_mode))
            if not isinstance(error, BrokenPipeError) and not windows_closed_pipe:
                raise
            # Avoid a second BrokenPipeError during interpreter shutdown.
            try:
                sys.stdout = open(os.devnull, "w")
            except OSError:
                pass
        return exit_code
    except InputError as error:
        print("infra-policy-checker: " + str(error), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("infra-policy-checker: Local input/output operation failed.", file=sys.stderr)
        return 2
    except Exception:
        # No raw exception, path, parser snippet or input-selected value escapes.
        print("infra-policy-checker: Internal analysis error.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
