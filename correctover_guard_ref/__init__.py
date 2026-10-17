"""Correctover Guard — open in-process reference layer (no signing core).

This package exposes the danger-rule surface, the evidence-view normalization
tier and the schema/rule adjudication chain needed to reproduce the G-G
parameter-risk benchmark. The proprietary fail-closed engine (independent
verifier, Ed25519 trust root, signed receipts) is not included.
"""

from .reference_guard import ReferenceDecision, ReferenceGuard
from .risk_router import PolicyProfile
from .risk_profile import profile_tool_schema

__all__ = [
    "ReferenceGuard",
    "ReferenceDecision",
    "PolicyProfile",
    "profile_tool_schema",
]

__version__ = "1.0.0"
