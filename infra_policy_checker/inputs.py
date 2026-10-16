"""Untrusted JSON boundary. Diagnostics deliberately contain no input fragments."""

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat

DEFAULT_LIMIT = 8 * 1024 * 1024
HARD_LIMIT = 32 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 200_000
MAX_RESOURCES = 2_000
POLICY_LIMIT = 256 * 1024
MISSING = object()
UNKNOWN = object()


class InputError(Exception):
    """A safe, static diagnostic suitable for stderr."""


def require(condition, message="Invalid supported plan structure."):
    if not condition:
        raise InputError(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON object key.")
        result[key] = value
    return result


def _constant(_):
    raise InputError("Non-finite JSON number.")


def parse_json(text, *, depth=MAX_DEPTH):
    # Check depth before json.loads, with escaped quotes and brackets in strings
    # handled independently of structural delimiters.
    level = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            level += 1
            require(level <= depth, "JSON nesting limit exceeded.")
        elif char in "]}":
            level -= 1
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError, OverflowError):
        raise InputError("Invalid JSON document.") from None
    pending = [value]
    nodes = 0
    while pending:
        current = pending.pop()
        nodes += 1
        require(nodes <= MAX_NODES, "JSON node limit exceeded.")
        if isinstance(current, dict):
            pending.extend(current.values())
            # Lone UTF-16 surrogates are accepted by json.loads, but are not
            # valid Unicode scalar values and can break downstream encoders.
            require(all(not any(0xD800 <= ord(c) <= 0xDFFF for c in k)
                        for k in current), "Invalid Unicode scalar value.")
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, str):
            require(not any(0xD800 <= ord(c) <= 0xDFFF for c in current),
                    "Invalid Unicode scalar value.")
        elif isinstance(current, float):
            import math
            require(math.isfinite(current), "Non-finite JSON number.")
    return value


def bounded_read(stream, limit):
    """Read no more than limit+1 bytes, including from a non-seekable stream."""
    chunks = []
    remaining = limit + 1
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    require(len(raw) <= limit, "Input byte limit exceeded.")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise InputError("Input must be valid UTF-8.") from None


def read_input(path, stream, limit):
    if path == "-":
        return parse_json(bounded_read(stream, limit))
    # Reject links, devices, sockets and pipes before opening. O_NONBLOCK and
    # descriptor fstat defend the open against a FIFO substitution where offered.
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            "Input must be a regular, non-symlink file.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode),
                "Input must be a regular file.")
        return parse_json(bounded_read(source, limit))


def mask_valid(mask):
    if type(mask) is bool:
        return
    if isinstance(mask, dict):
        for item in mask.values():
            mask_valid(item)
    elif isinstance(mask, list):
        for item in mask:
            mask_valid(item)
    else:
        raise InputError("Invalid recursive evidence mask.")


def mask_shape(mask, value):
    """Reject container/type contradictions that could otherwise hide unknowns."""
    if type(mask) is bool:
        return
    if value is not MISSING and value is not None:
        require(isinstance(value, type(mask)), "Evidence mask container mismatch.")
    if isinstance(mask, dict):
        for key, child in mask.items():
            mask_shape(child, value.get(key, MISSING) if isinstance(value, dict) else MISSING)
    elif isinstance(mask, list):
        for index, child in enumerate(mask):
            mask_shape(child, value[index] if isinstance(value, list) and index < len(value)
                       else MISSING)


def any_true(mask):
    if mask is True:
        return True
    if isinstance(mask, dict):
        return any(any_true(v) for v in mask.values())
    if isinstance(mask, list):
        return any(any_true(v) for v in mask)
    return False


def sensitive_plan(plan):
    # Conservatively suppress every address label when ANY marked sensitivity
    # is present. Values are never rendered, even when no mask is supplied.
    pending = [plan]
    sensitive = False
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"after_sensitive", "before_sensitive", "sensitive_values"}:
                    mask_valid(item)
                    sensitive |= any_true(item)
                else:
                    pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)
    return sensitive


def evidence(value, mask, path):
    """Return (state, value); true at ANY ancestor overrides apparent values."""
    for key in path:
        if mask is True:
            return "unknown", UNKNOWN
        if isinstance(mask, dict):
            mask = mask.get(key, False)
        elif isinstance(mask, list):
            mask = mask[key] if isinstance(key, int) and key < len(mask) else False
        else:
            mask = False
        if isinstance(value, dict):
            value = value.get(key, MISSING)
        elif isinstance(value, list) and isinstance(key, int) and key < len(value):
            value = value[key]
        else:
            value = MISSING
    if mask is True:
        return "unknown", UNKNOWN
    if value is MISSING:
        return "missing", value
    if value is None:
        return "null", value
    return "known", value


def descendant_unknown(mask):
    return any_true(mask)


def fingerprint(address, deposed=None):
    identity = json.dumps([address, deposed], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(identity.encode("ascii")).hexdigest()


def address_label(address, sensitive=False):
    if sensitive:
        return "<sensitive-resource>"
    # Terraform quoted instance keys may contain private names or arbitrary text.
    redacted = re.sub(r'\["(?:[^"\\]|\\.)*"\]', '["<redacted>"]', address)
    # ASCII allowlist also escapes terminal controls, Unicode bidi and newlines.
    safe = "".join(c if c.isascii() and (c.isalnum() or c in '._-[]"<>')
                   else "\\u%04x" % ord(c) for c in redacted)
    return safe[:240] + ("..." if len(safe) > 240 else "")


@dataclass(frozen=True)
class Resource:
    index: int
    address: str
    previous_address: str | None
    deposed: str | None
    mode: str
    kind: str
    actions: tuple
    after: object
    unknown: object

    @property
    def pointer(self):
        return f"/resource_changes/{self.index}"


def validate_plan(plan):
    require(isinstance(plan, dict), "Expected one plan JSON object.")
    version = plan.get("format_version")
    require(isinstance(version, str) and re.fullmatch(r"1\.[0-9]+", version) is not None,
            "Unsupported or missing plan format_version; major 1 required.")
    require(isinstance(plan.get("planned_values"), dict),
            "Expected saved-plan planned_values; state and event streams are unsupported.")
    for key in ("complete", "errored"):
        if key in plan:
            require(type(plan[key]) is bool, "Plan status must be a JSON boolean.")
    changes = plan.get("resource_changes", [])
    require(isinstance(changes, list), "resource_changes must be an array.")
    require(len(changes) <= MAX_RESOURCES, "Resource count limit exceeded.")
    deferred = plan.get("deferred_changes", [])
    require(isinstance(deferred, list) and len(deferred) <= MAX_RESOURCES,
            "Invalid deferred_changes structure.")
    for item in deferred:
        require(isinstance(item, dict) and isinstance(item.get("reason"), str)
                and isinstance(item.get("resource_change"), dict),
                "Invalid deferred_changes structure.")
    resources = []
    seen = set()
    for index, raw in enumerate(changes):
        require(isinstance(raw, dict))
        address, kind, mode = (raw.get(k) for k in ("address", "type", "mode"))
        require(isinstance(address, str) and 0 < len(address) <= 4096)
        require(isinstance(kind, str) and 0 < len(kind) <= 128
                and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", kind) is not None)
        require(mode in ("managed", "data"))
        previous, deposed = raw.get("previous_address"), raw.get("deposed")
        if "previous_address" in raw:
            require(isinstance(previous, str) and 0 < len(previous) <= 4096)
        if "deposed" in raw:
            require(isinstance(deposed, str) and 0 < len(deposed) <= 256)
        identity = (address, deposed)
        require(identity not in seen, "Duplicate resource identity or contradictory current records.")
        seen.add(identity)
        change = raw.get("change")
        require(isinstance(change, dict))
        actions = change.get("actions")
        require(isinstance(actions, list) and 1 <= len(actions) <= 4
                and all(isinstance(a, str) and len(a) <= 32 for a in actions),
                "Invalid change action structure.")
        require("after" in change, "Change is missing after evidence.")
        after = change["after"]
        require(after is None or isinstance(after, dict), "Change after must be an object or null.")
        unknown = change.get("after_unknown", {})
        mask_valid(unknown)
        mask_shape(unknown, after)
        resources.append(Resource(index, address, previous, deposed, mode, kind,
                                  tuple(actions), after, unknown))
    return resources
