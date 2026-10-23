"""Z3 μZ Datalog encoder for mined ABAC policies.

Re-exports from sub-modules for clean import paths. The ABACEncoder
class remains in the monolithic abac_encoder.py for now — it will be
moved to encoder/encoder.py in a future refactor step.
"""

# New modular imports
from rlm_agent.encoder.parser import load_policy, _lenient_json, validate_ir
from rlm_agent.encoder.catalog import _extract_catalog, _safe_enum_name
from rlm_agent.encoder.nvd import (
    nvd_check_affects,
    _normalize_to_upstream,
    _parse_version,
    _version_in_range,
    _CPE_PRODUCT_ALIASES,
)

# ABACEncoder still lives in the monolith — re-export for convenience
try:
    from rlm_agent.abac_encoder import ABACEncoder
except ImportError:
    # Circular import guard — abac_encoder.py imports from here during init
    pass

__all__ = [
    "ABACEncoder",
    "load_policy",
    "validate_ir",
    "nvd_check_affects",
    "_extract_catalog",
    "_safe_enum_name",
]
