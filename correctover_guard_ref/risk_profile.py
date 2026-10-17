"""G-G canonical parameter-risk profiling for MCP tool JSON Schemas.

This module is the *schema-driven* half of risk-aware routing.  Given a
tool's input JSON Schema it deterministically assigns the five canonical
``gg:`` risk-class labels defined in the Correctover G-G Internet-Draft
(``draft-correctover-gg-mcp-parameter-risk``):

    gg:credential-value   gg:filesystem-path   gg:command-string
    gg:money-amount       gg:url-endpoint

Lexical rules are a faithful re-implementation of the archived normative
classification suite (``atlas_analyze.py`` / ``PARAM_CLASSES`` +
``param_hits``, Zenodo audit record 10.5281/zenodo.23333516).  The two
high-recall non-normative buckets (``account_identity`` /
``raw_content_blob``) are reproduced *only* for corpus comparability and
are deliberately excluded from ``CANONICAL_CLASSES`` so policy can never
grant/deny containment on them by accident.

A label says *a parameter is capable of carrying* a risky value; it never
sees the value itself (in particular credential labels never contain the
secret).  Value-level attack detection stays in :mod:`rules`; labels only
decide which containment predicates are in force for which parameters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Canonical gg: identifiers (normative five), keyed by the archived suite's
# internal class token so the regex table stays byte-comparable.
CLASS_TOKEN_TO_LABEL = {
    "credential_value": "gg:credential-value",
    "filesystem_path": "gg:filesystem-path",
    "command_string": "gg:command-string",
    "money_amount": "gg:money-amount",
    "url_endpoint": "gg:url-endpoint",
}
CANONICAL_CLASSES: Tuple[str, ...] = tuple(CLASS_TOKEN_TO_LABEL)

# Non-normative high-recall buckets (Section 5 of the I-D).  Kept for corpus
# comparability only; never used by PolicyProfile containment decisions.
NON_NORMATIVE_BUCKETS = ("account_identity", "raw_content_blob")

# Left/right token boundary: negative lookbehind/lookahead over ASCII lower,
# digits and underscore (I-D Section 3.3).  re.I provides the Unicode
# case-insensitive substring (search) match the suite uses.
_BOUND_L = r"(?<![a-z0-9_])"
_BOUND_R = r"(?![a-z0-9_])"

# Exact pattern table from the archived normative suite.  Multi-line string
# concatenation reproduces the same single-line regular expressions.
_PARAM_CLASSES: Dict[str, Tuple[str, ...]] = {
    "filesystem_path": (
        _BOUND_L
        + r"(path|filepath|filename|file_path|dir|directory|"
        r"folder|target_path|destination_path|dest_path)"
        + _BOUND_R,
    ),
    "url_endpoint": (
        _BOUND_L
        + r"(url|uri|endpoint|webhook_url|target_url|host|"
        r"hostname|domain|link|webhook|base_url|callback_url)"
        + _BOUND_R,
    ),
    "command_string": (
        _BOUND_L
        + r"(command|cmd|script|code|expression|sql|"
        r"statement|shell_cmd|args?|arguments?|instruction|prompt)"
        + _BOUND_R,
    ),
    "money_amount": (
        _BOUND_L
        + r"(amount|price|total|sum|currency|"
        r"refund_amount|charge_amount|unit_amount|cents)"
        + _BOUND_R,
        r"\b(amount in|monetary|currency code)\b",
    ),
    # Non-normative bucket (kept for comparability).
    "account_identity": (
        _BOUND_L
        + r"(account|account_id|iban|wallet|recipient|"
        r"customer_id|user_id|beneficiary|card_token|"
        r"payment_method|bank|routing_number)"
        + _BOUND_R,
        _BOUND_L + r"(email|to|from)" + _BOUND_R,
    ),
    "credential_value": (
        _BOUND_L
        + r"(token|apikey|api_key|secret|password|passwd|"
        r"private_key|access_key|credential|client_secret|bearer|"
        r"authorization)"
        + _BOUND_R,
    ),
    # Non-normative bucket (kept for comparability).
    "raw_content_blob": (
        _BOUND_L
        + r"(content|body|data|payload|html|markdown|"
        r"file_content|text)"
        + _BOUND_R,
    ),
}
_COMPILED = {
    token: [re.compile(p, re.I) for p in pats]
    for token, pats in _PARAM_CLASSES.items()
}


def iter_schema_properties(schema: Any):
    """Yield ``(name, description, required)`` per I-D Section 3.1.

    Top-level ``properties`` are enumerated; when absent, object schemas
    nested under a top-level ``definitions``/``$defs`` that themselves carry
    ``properties`` are enumerated instead.  This mirrors the archived suite:
    a top-level properties object short-circuits definition enumeration.
    """
    if not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        req = set(schema.get("required") or [])
        for name, spec in props.items():
            desc = str(spec.get("description") or "") if isinstance(
                spec, dict) else ""
            yield str(name), desc, str(name) in req
        return
    for defkey in ("definitions", "$defs"):
        defs = schema.get(defkey)
        if isinstance(defs, dict):
            for _, dspec in defs.items():
                if isinstance(dspec, dict) and isinstance(
                        dspec.get("properties"), dict):
                    dreq = set(dspec.get("required") or [])
                    for name, spec in dspec["properties"].items():
                        desc = str(spec.get("description", "")) if isinstance(
                            spec, dict) else ""
                        yield str(name), desc, str(name) in dreq


def classify_property(name: str, description: str) -> Tuple[str, ...]:
    """Return canonical gg labels for one property (multi-label capable)."""
    haystack = (str(name) + " : " + str(description)).lower()
    labels: List[str] = []
    for token in CANONICAL_CLASSES:
        if any(p.search(haystack) for p in _COMPILED[token]):
            labels.append(CLASS_TOKEN_TO_LABEL[token])
    return tuple(labels)


@dataclass(frozen=True)
class LabeledParam:
    """One parameter property with its assigned risk labels."""

    name: str
    labels: Tuple[str, ...]
    required: bool


@dataclass
class RiskProfile:
    """The per-tool G-G risk profile derived purely from its JSON Schema.

    Attributes:
        tool: tool name this profile belongs to.
        labeled: parameters carrying at least one canonical gg label.
        labels_by_tool: every canonical label present on at least one param.
        required_labels: canonical labels with at least one required param.
        non_normative: non-normative bucket hits (informational only).
        schema_present: False when no usable object schema was supplied.
    """

    tool: str
    labeled: List[LabeledParam] = field(default_factory=list)
    labels_by_tool: Tuple[str, ...] = ()
    required_labels: Tuple[str, ...] = ()
    non_normative: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    schema_present: bool = True

    # -- convenient lookups ------------------------------------------------
    def param_names(self, label: str) -> Tuple[str, ...]:
        return tuple(p.name for p in self.labeled if label in p.labels)

    def has(self, label: str) -> bool:
        return label in self.labels_by_tool

    @property
    def is_empty(self) -> bool:
        return not self.labeled

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "schema_present": self.schema_present,
            "labels": list(self.labels_by_tool),
            "required_labels": list(self.required_labels),
            "params": [
                {"name": p.name, "labels": list(p.labels),
                 "required": p.required}
                for p in self.labeled
            ],
            "non_normative": {k: list(v)
                              for k, v in self.non_normative.items()},
        }


def profile_tool_schema(
    tool: str,
    schema: Optional[dict],
) -> RiskProfile:
    """Derive the canonical G-G :class:`RiskProfile` from a tool schema."""
    labeled: List[LabeledParam] = []
    required_set = set()
    non_normative: Dict[str, Tuple[str, ...]] = {}

    if not isinstance(schema, dict) or not isinstance(
            schema.get("properties"), dict):
        # No top-level properties: either no schema or only nested defs.  Run
        # the enumerator for the defs-only case; mark schema_present by whether
        # the input was a usable object at all.
        props = list(iter_schema_properties(schema))
        if not props:
            return RiskProfile(tool=tool, schema_present=bool(schema))
        candidates = props
        present = True
    else:
        candidates = list(iter_schema_properties(schema))
        present = True

    for name, desc, required in candidates:
        labels = classify_property(name, desc)
        if labels:
            labeled.append(LabeledParam(name, labels, required))
            if required:
                required_set.update(labels)
        haystack = (name + " : " + desc).lower()
        for bucket in NON_NORMATIVE_BUCKETS:
            if any(p.search(haystack) for p in _COMPILED[bucket]):
                non_normative.setdefault(bucket, ())
                non_normative[bucket] = non_normative[bucket] + (name,)

    all_labels = tuple(
        lbl for lbl in CLASS_TOKEN_TO_LABEL.values()
        if any(lbl in p.labels for p in labeled)
    )
    return RiskProfile(
        tool=tool,
        labeled=labeled,
        labels_by_tool=all_labels,
        required_labels=tuple(lbl for lbl in all_labels if lbl in required_set),
        non_normative=non_normative,
        schema_present=present,
    )
