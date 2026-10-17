"""In-process *reference* guard for the G-G parameter-risk benchmark.

This module deliberately contains **no cross-process isolation, no Ed25519
trust anchor and no signed-receipt kernel**. It is a self-contained,
standard-library-only re-implementation of the single decision chain that the
production Correctover engine runs in its in-process mode, so that a third
party can reproduce every benchmark verdict from the frozen pool without any
proprietary component:

    profile schema -> evaluate operator policy -> value-rule scan with the
    schema-widened execution tier (including read-only evidence views)

The production fail-closed engine (independent verifier process, pinned
Ed25519 trust root, signed adjudication receipts) is proprietary and is NOT
part of this repository. See README.md and STANDARD.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from .risk_profile import profile_tool_schema
from .risk_router import (
    PolicyProfile,
    evaluate_policy,
    execution_param_names,
    inspect_with_execution_keys,
)
from .rules import GuardRule, default_rules


@dataclass
class ReferenceDecision:
    """A plain verdict. There is deliberately no cryptographic receipt here."""

    allowed: bool
    verdict: str                       # "allow" | "deny"
    rule_id: str = ""
    block_reason: str = ""
    warnings: List[str] = field(default_factory=list)
    risk_labels: List[str] = field(default_factory=list)


class ReferenceGuard:
    """In-process, single-call adjudicator over the open rule surface.

    Unlike the production guard this never leaves the caller's process and
    issues no independently verifiable receipt; it is suitable for offline
    benchmarking and for understanding the decision logic, not for
    fail-closed enforcement against a compromised host.
    """

    def __init__(
        self,
        policy: Optional[PolicyProfile] = None,
        rule_list: Optional[List[GuardRule]] = None,
    ) -> None:
        self.policy = policy or PolicyProfile()
        self._rules = (
            rule_list if rule_list is not None else default_rules()
        )

    def check(
        self,
        tool: str,
        params: dict,
        schema: Optional[dict] = None,
        trace: Optional[str] = None,  # accepted for interface compatibility
    ) -> ReferenceDecision:
        profile = profile_tool_schema(tool, schema)
        policy_decision = evaluate_policy(profile, params, self.policy)
        warnings = list(policy_decision.warnings)

        if policy_decision.denied:
            rule_id = policy_decision.rule_id
        else:
            rule_id = inspect_with_execution_keys(
                params,
                extra_execution_keys=execution_param_names(profile),
                rule_list=self._rules,
            ) or ""

        verdict = "deny" if rule_id else "allow"
        return ReferenceDecision(
            allowed=(verdict == "allow"),
            verdict=verdict,
            rule_id=rule_id,
            block_reason="" if verdict == "allow"
            else "blocked by rule %s" % rule_id,
            warnings=warnings,
            risk_labels=list(profile.labels_by_tool),
        )
