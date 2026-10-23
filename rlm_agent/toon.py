"""
TOON (Token-Oriented Object Notation) v3 encoder.

A compact JSON → TOON encoder used to shrink vulnx responses before
feeding them to the LLM. Saves ~40-60% tokens vs JSON for typical
vulnx output by rendering uniform object arrays as tabular rows.

Spec: https://github.com/toon-format/spec/blob/main/SPEC.md
"""

import json
import re

_USE_TOON = False  # flipped on by --toon


def _toon_needs_quoting(s: str, delim: str = ",") -> bool:
    if not s or s != s.strip():
        return True
    if any(c in s for c in (delim, ":", "\n", "\r", "\t", "[", "]", "{", "}", '"', "\\", "-")):
        return True
    if s in ("true", "false", "null"):
        return True
    try:
        float(s)
        return True
    except ValueError:
        return False


def _toon_quote(s: str) -> str:
    escaped = (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _toon_primitive(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            return "null"
        return str(int(v)) if v.is_integer() else format(v, "g")
    if isinstance(v, str):
        return v if not _toon_needs_quoting(v) else _toon_quote(v)
    return _toon_quote(str(v))


_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _toon_key(key: str) -> str:
    return key if _KEY_RE.fullmatch(key) else _toon_quote(key)


def _is_uniform_primitive_objects(arr: list) -> tuple:
    """True iff every element is a dict with the same key-set and only primitive values."""
    if not arr or not all(isinstance(x, dict) for x in arr):
        return False, []
    keys = list(arr[0].keys())
    keyset = set(keys)
    for item in arr:
        if set(item.keys()) != keyset:
            return False, []
        for val in item.values():
            if isinstance(val, (dict, list)):
                return False, []
    return True, keys


def _toon_emit(value, indent: int, key) -> list:
    pad = "  " * indent
    out: list = []
    prefix = f"{_toon_key(key)}" if key is not None else ""

    if isinstance(value, dict):
        if key is None:
            for k, v in value.items():
                out.extend(_toon_emit(v, indent, k))
        elif not value:
            out.append(f"{pad}{prefix}:")
        else:
            out.append(f"{pad}{prefix}:")
            for k, v in value.items():
                out.extend(_toon_emit(v, indent + 1, k))
        return out

    if isinstance(value, list):
        header_key = prefix
        n = len(value)
        if n == 0:
            out.append(f"{pad}{header_key}[0]:")
            return out

        if all(not isinstance(x, (dict, list)) for x in value):
            inline = ",".join(_toon_primitive(x) for x in value)
            out.append(f"{pad}{header_key}[{n}]: {inline}")
            return out

        uniform, fields = _is_uniform_primitive_objects(value)
        if uniform:
            field_list = ",".join(_toon_key(f) for f in fields)
            out.append(f"{pad}{header_key}[{n}]{{{field_list}}}:")
            for item in value:
                row = ",".join(_toon_primitive(item[f]) for f in fields)
                out.append(f"{pad}  {row}")
            return out

        out.append(f"{pad}{header_key}[{n}]:")
        for item in value:
            if isinstance(item, dict):
                if not item:
                    out.append(f"{pad}  - {{}}")
                    continue
                items = list(item.items())
                first_k, first_v = items[0]
                if isinstance(first_v, (dict, list)):
                    out.append(f"{pad}  -")
                    for k, v in items:
                        out.extend(_toon_emit(v, indent + 2, k))
                else:
                    out.append(f"{pad}  - {_toon_key(first_k)}: {_toon_primitive(first_v)}")
                    for k, v in items[1:]:
                        out.extend(_toon_emit(v, indent + 2, k))
            elif isinstance(item, list):
                sub_n = len(item)
                if all(not isinstance(x, (dict, list)) for x in item):
                    inline = ",".join(_toon_primitive(x) for x in item)
                    out.append(f"{pad}  - [{sub_n}]: {inline}")
                else:
                    out.append(f"{pad}  - [{sub_n}]:")
                    for sub in item:
                        out.extend(_toon_emit(sub, indent + 2, None))
            else:
                out.append(f"{pad}  - {_toon_primitive(item)}")
        return out

    if key is None:
        out.append(f"{pad}{_toon_primitive(value)}")
    else:
        out.append(f"{pad}{prefix}: {_toon_primitive(value)}")
    return out


def json_to_toon(value) -> str:
    """Encode a JSON-compatible Python value as TOON v3 text."""
    return "\n".join(_toon_emit(value, indent=0, key=None))


def _maybe_toon(raw_json: str) -> str:
    """If --toon is on, convert a JSON (or JSONL) string to TOON."""
    if not _USE_TOON or not raw_json.strip():
        return raw_json
    try:
        return json_to_toon(json.loads(raw_json))
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        rows = [json.loads(line) for line in raw_json.splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError):
        return raw_json
    if not rows:
        return raw_json
    return json_to_toon({"results": rows})
