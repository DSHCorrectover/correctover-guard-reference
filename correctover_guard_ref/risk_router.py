"""Schema-driven policy evaluation for one profiled tool call.

The :class:`~correctover_guard.risk_profile.RiskProfile` only says which
parameters *can* carry risky values.  This module decides what that means at
call time, independently inside the verifier:

* value-level attack rules run with the execution tier widened to every
  ``gg:command-string`` parameter (not just the hard-coded execution keys);
* ``gg:money-amount`` parameters can be bounded per parameter;
* a credential-value parameter sent together with a populated
  ``gg:url-endpoint`` parameter is a credential-exfiltration *signal* —
  warn by default (benign legit-client cases exist), block only when the
  operator opts into fail-closed containment;
* a tool presented without a usable schema is value-checked by default; with
  ``strict_missing_schema`` the verifier denies until a profile exists.

Everything here is deterministic and value-only: no model, no network.  A
denial produces a stable ``gg:`` rule id; non-denying observations are
returned as warnings so they are auditable without changing the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional
from urllib.parse import urlparse

from . import rules
from .normalization import candidate_views
from .risk_profile import RiskProfile

# Stable deny rule ids (distinct namespace from the value-rule engine).
RULE_MONEY_BOUND = "gg:money-bound-exceeded"
RULE_NO_SCHEMA = "gg:no-schema-profile"
RULE_CRED_EXFIL = "gg:credential-exfiltration"

WARN_CRED_EXFIL = "gg:w:credential-exfiltration-signal"

CRED_LABEL = "gg:credential-value"
URL_LABEL = "gg:url-endpoint"
MONEY_LABEL = "gg:money-amount"
COMMAND_LABEL = "gg:command-string"


@dataclass
class PolicyProfile:
    """Operator containment policy held by the independent verifier."""

    # Deny calls for which no usable tool schema could be profiled.
    strict_missing_schema: bool = False
    # Per-parameter inclusive upper bound for gg:money-amount values.
    money_limits: Dict[str, float] = field(default_factory=dict)
    # "warn" (default): audit only; "block": fail-closed deny; "off": ignore.
    credential_exfil: str = "warn"


@dataclass
class PolicyDecision:
    rule_id: str = ""
    warnings: List[str] = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return bool(self.rule_id)


def execution_param_names(profile: RiskProfile) -> FrozenSet[str]:
    """Top-level parameter names whose schema carries gg:command-string."""
    return frozenset(profile.param_names(COMMAND_LABEL))


def inspect_with_execution_keys(
    args: object,
    *,
    extra_execution_keys: Optional[FrozenSet[str]] = None,
    rule_list: Optional[List[rules.GuardRule]] = None,
    max_scan_bytes: int = rules.MAX_SCAN_BYTES,
) -> Optional[str]:
    """Value-rule scan with a schema-widened execution tier.

    Mirrors :func:`rules.inspect_tool_arguments` (one decrementing byte
    budget, fail-closed on scan overflow) but a key is also treated as an
    execution context when the G-G profile labels it ``gg:command-string``.
    """
    active = rule_list if rule_list is not None else rules.default_rules()
    extra = extra_execution_keys or frozenset()
    budget = max_scan_bytes

    def scan(node: object, execution: bool) -> Optional[str]:
        nonlocal budget
        if isinstance(node, str):
            if len(node) > budget:
                return rules.SCAN_LIMIT_RULE_ID
            budget -= len(node)
            # Pass 1: test the original value against every in-scope rule.
            # This preserves rule-order / original-first semantics and keeps
            # benign large inputs on the same single-pass cost as a scanner
            # without normalization.
            for rule in active:
                if rule.scope == rules.SCOPE_EXECUTION and not execution:
                    continue
                if rule.test(node):
                    return rule.id
            # Pass 2: original clean -> generate evidence views (bounded) and
            # re-run in-scope rules to surface encoded/spliced payloads.
            views = candidate_views(node)
            extra_views = views[1:]
            for view in extra_views:
                if len(view) > budget:
                    return rules.SCAN_LIMIT_RULE_ID
                budget -= len(view)
            if extra_views:
                for rule in active:
                    if rule.scope == rules.SCOPE_EXECUTION and not execution:
                        continue
                    for view in extra_views:
                        if rule.test(view):
                            return rule.id
            return None
        if isinstance(node, list):
            for item in node:
                hit = scan(item, execution)
                if hit:
                    return hit
            return None
        if isinstance(node, dict):
            for key, value in node.items():
                k = str(key)
                ex = execution or rules.is_execution_key(k) or k in extra
                hit = scan(value, ex)
                if hit:
                    return hit
        return None

    return scan(args, False)


def _as_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _looks_like_endpoint(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlparse(value.strip())
    return parsed.scheme.lower() in ("http", "https") and bool(parsed.netloc)


def evaluate_policy(
    profile: RiskProfile,
    params: dict,
    config: Optional[PolicyProfile] = None,
) -> PolicyDecision:
    """Return the first containment denial plus any audit warnings."""
    cfg = config or PolicyProfile()
    out = PolicyDecision()

    if not profile.schema_present and cfg.strict_missing_schema:
        out.rule_id = RULE_NO_SCHEMA
        return out

    if not isinstance(params, dict):
        return out

    # Money bounds (inclusive).  Only parameters the schema labels as money.
    # Each schema-labelled value is tested across its evidence views, so an
    # amount hidden as Base64/hex or written in scientific notation is still
    # bounded; the original value is always tested first.
    for name, bound in cfg.money_limits.items():
        if name in profile.param_names(MONEY_LABEL) and name in params:
            raw = params[name]
            candidates = candidate_views(raw) if isinstance(raw, str) else [raw]
            for view in candidates:
                number = _as_number(view)
                if number is not None and number > bound:
                    out.rule_id = RULE_MONEY_BOUND
                    return out

    # Credential value + populated external endpoint = exfiltration signal.
    if cfg.credential_exfil != "off":
        has_cred = any(
            isinstance(params.get(n), str) and params[n] != ""
            for n in profile.param_names(CRED_LABEL)
        )
        endpoint_filled = any(
            any(_looks_like_endpoint(v) for v in candidate_views(params.get(n)))
            if isinstance(params.get(n), str)
            else _looks_like_endpoint(params.get(n))
            for n in profile.param_names(URL_LABEL)
        )
        if has_cred and endpoint_filled:
            if cfg.credential_exfil == "block":
                out.rule_id = RULE_CRED_EXFIL
                return out
            out.warnings.append(WARN_CRED_EXFIL)

    return out
