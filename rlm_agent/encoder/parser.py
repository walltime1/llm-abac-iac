"""Policy parser — extract JSON from .md or load raw JSON."""

import json
import re
from pathlib import Path


def load_policy(path: str) -> dict:
    """Load a policy from a .md file (abac_poc output) or raw JSON file."""
    text = Path(path).read_text()

    # Try raw JSON first
    try:
        obj = json.loads(text)
        if "rules" in obj:
            return obj
    except (json.JSONDecodeError, ValueError):
        pass

    # Extract from markdown fences
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    if len(blocks) < 2:
        raise ValueError(f"Expected at least 2 JSON blocks in {path} (attributes + rules)")

    attrs = _lenient_json(blocks[0])
    rules = _lenient_json(blocks[1])
    vulns = _lenient_json(blocks[2]) if len(blocks) > 2 else []
    return {"attributes": attrs, "rules": rules, "vulnerabilities": vulns}


def _lenient_json(raw: str):
    """Parse JSON leniently, recovering from common LLM output errors."""
    raw = raw.strip()
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(raw)
        return obj
    except (json.JSONDecodeError, ValueError):
        pass
    return json.loads(raw)


def validate_ir(policy: dict) -> None:
    """Validate policy against ir_schema.json if jsonschema is available."""
    try:
        import jsonschema
    except ImportError:
        return
    schema_path = Path(__file__).parent.parent / "ir_schema.json"
    if not schema_path.exists():
        return
    schema = json.loads(schema_path.read_text())
    try:
        jsonschema.validate(policy, schema)
    except jsonschema.ValidationError as e:
        print(f"[schema] IR validation warning: {e.message}")
