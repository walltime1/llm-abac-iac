"""ABAC policy mining from Ansible configurations.

The core implementation remains in abac_poc.py. This package provides
clean import paths and will house the decomposed modules as the
refactor progresses.
"""

# Re-export for clean import paths
# These require dspy — will fail gracefully if not installed
try:
    from rlm_agent.abac_poc import (
        ABACPolicyMiningSignature,
        ABACPolicyMiningSignatureLazy,
        mine_policy,
        build_abac_rlm,
    )
except ImportError:
    pass
