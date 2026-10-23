"""
Ansible config access tools for the RLM.

The directory to mine is selected via the RLM_ANSIBLE_DIR env var (absolute
or resolved against the current working directory). The RLM never sees the
full directory contents in its prompt — it calls list_ansible_files() to
discover them and read_ansible_file() to load a specific one.

Return values are **native Python objects** (lists, dicts, strings), not
JSON-encoded strings, so the RLM-generated Python can index them directly
(e.g. `for f in list_ansible_files(): read_ansible_file(f['path'])`).

Read-only. Symlinks out of the root are rejected.
"""

import os
from pathlib import Path
from typing import Optional


ANSIBLE_DIR_ENV = "RLM_ANSIBLE_DIR"
_TEXT_EXTS = {".yml", ".yaml", ".ini", ".cfg", ".j2", ".txt", ".md"}
_MAX_BYTES = 256 * 1024  # 256 KiB — don't flood the LLM with a binary dump


def _root() -> Path:
    raw = os.environ.get(ANSIBLE_DIR_ENV)
    if not raw:
        raise RuntimeError(
            f"{ANSIBLE_DIR_ENV} is not set. "
            "Point it at the Ansible directory before starting the RLM, e.g.\n"
            "  export RLM_ANSIBLE_DIR=$(pwd)/ansible_configs"
        )
    p = Path(raw).expanduser().resolve()
    if not p.is_dir():
        raise RuntimeError(f"{ANSIBLE_DIR_ENV}={raw} is not a directory.")
    return p


def _safe_join(rel: str) -> Path:
    """Join rel onto the root, refusing any path that escapes it."""
    root = _root()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise RuntimeError(f"Path {rel!r} escapes {ANSIBLE_DIR_ENV}.") from None
    return candidate


def list_ansible_files(subdir: Optional[str] = None) -> list:
    """
    List Ansible-relevant text files under RLM_ANSIBLE_DIR (or a subdir).

    Returns a list of relative path strings (e.g. 'group_vars/all.yml').
    Use read_ansible_file(path) to read any returned path.

    Args:
        subdir: optional subdirectory relative to RLM_ANSIBLE_DIR
    """
    root = _root()
    base = _safe_join(subdir) if subdir else root
    entries: list = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _TEXT_EXTS:
            continue
        entries.append(str(path.relative_to(root)))
    return entries


def read_ansible_file(path: str) -> str:
    """
    Read a single Ansible file relative to RLM_ANSIBLE_DIR.

    Returns the file's text content as a string (truncated with a marker
    comment if above the safety limit). Raises RuntimeError for missing
    files or path escapes.

    Args:
        path: path relative to RLM_ANSIBLE_DIR (e.g. 'roles/webserver/tasks/main.yml')
    """
    target = _safe_join(path)
    if not target.is_file():
        raise RuntimeError(f"Not a file: {path}")
    size = target.stat().st_size
    with target.open("rb") as f:
        blob = f.read(_MAX_BYTES + 1)
    truncated = len(blob) > _MAX_BYTES
    text = blob[:_MAX_BYTES].decode("utf-8", errors="replace")
    if truncated:
        text += f"\n\n# …truncated at {_MAX_BYTES} bytes of {size}…\n"
    return text


ANSIBLE_TOOLS = [list_ansible_files, read_ansible_file]
