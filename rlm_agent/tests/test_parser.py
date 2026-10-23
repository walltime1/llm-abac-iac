"""Tests for policy parser and lenient JSON handling."""

import json
import tempfile
from pathlib import Path

import pytest
from rlm_agent.encoder.parser import load_policy, _lenient_json


class TestLenientJson:
    def test_valid_json(self):
        result = _lenient_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_valid_json_array(self):
        result = _lenient_json('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_trailing_brace(self):
        """Extra closing brace after valid JSON — common LLM error."""
        result = _lenient_json('{"key": "value"}}')
        assert result == {"key": "value"}

    def test_trailing_whitespace_and_brace(self):
        result = _lenient_json('{"key": "value"}\n}\n')
        assert result == {"key": "value"}

    def test_completely_invalid(self):
        with pytest.raises(json.JSONDecodeError):
            _lenient_json("not json at all")

    def test_empty_string(self):
        with pytest.raises(json.JSONDecodeError):
            _lenient_json("")


class TestLoadPolicy:
    def test_load_raw_json(self, tmp_path):
        policy = {"attributes": {}, "rules": [{"id": "r1"}], "vulnerabilities": []}
        f = tmp_path / "policy.json"
        f.write_text(json.dumps(policy))
        result = load_policy(str(f))
        assert result["rules"] == [{"id": "r1"}]

    def test_load_markdown(self, tmp_path):
        md = """# Policy

```json
{"subjects": {"users": [{"name": "alice"}]}}
```

```json
[{"id": "rule-001", "action": "ssh:login"}]
```

```json
[]
```
"""
        f = tmp_path / "policy.md"
        f.write_text(md)
        result = load_policy(str(f))
        assert result["attributes"]["subjects"]["users"][0]["name"] == "alice"
        assert result["rules"][0]["id"] == "rule-001"
        assert result["vulnerabilities"] == []

    def test_load_markdown_two_blocks(self, tmp_path):
        """Two JSON blocks (no vulnerabilities) should work."""
        md = """```json
{"subjects": {}}
```

```json
[]
```
"""
        f = tmp_path / "policy.md"
        f.write_text(md)
        result = load_policy(str(f))
        assert result["vulnerabilities"] == []

    def test_load_markdown_one_block_fails(self, tmp_path):
        md = """```json
{"only": "one"}
```
"""
        f = tmp_path / "policy.md"
        f.write_text(md)
        with pytest.raises(ValueError, match="at least 2 JSON blocks"):
            load_policy(str(f))

    def test_lenient_markdown_trailing_brace(self, tmp_path):
        """Markdown with trailing garbage in a JSON block."""
        md = """```json
{"subjects": {"users": [{"name": "alice"}]}}
}
```

```json
[]
```
"""
        f = tmp_path / "policy.md"
        f.write_text(md)
        result = load_policy(str(f))
        assert result["attributes"]["subjects"]["users"][0]["name"] == "alice"
