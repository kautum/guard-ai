"""
Guard AI configuration constants (Part 7.5).
Fail-closed: if a constant is missing/None, callers must treat the
gated feature as disabled/most-restrictive, never default to permissive.
"""

DEPTH_CEILING = 3          # max delegation chain depth (SubAgent nesting)
CASCADE_CEILING = 10       # max transitive descendant count before fan-out forbid
OOD_THRESHOLD = 0.8        # ood_score above this triggers ASI10 routing
ROGUE_THRESHOLD = 0.8      # purpose_deviation_score above this triggers rogue-agent escalate
WARNING_FRACTION = 0.7     # fraction of ceiling that triggers early escalate warning


def require_configured(value, name: str):
    """Fail closed if a required constant is unset."""
    if value is None:
        raise RuntimeError(f"Guard AI config error: '{name}' is unset — failing closed.")
    return value