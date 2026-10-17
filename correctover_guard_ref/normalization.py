"""Deterministic value-normalization layer (evidence views, no mutation).

Attack payloads hide in encodings (Base64, ``\\xNN`` hex), Unicode
compatibility forms (full-width NFKC) and shell token splicing
(``'``'``, ``$(echo)``, ``$IFS``, inline comments).  The rule engine tests
*views* of every string: the original value is always tested first and is the
only value used for policy decisions and receipt hashing.  Additional views are
purely evidence for the high-confidence value rules; they never mutate the
caller's parameters.

Design constraints (all enforced):

* **Bounded**: every view is length-capped; a shared byte budget across all
  views keeps inspection linear and fail-closed.
* **Conservative decode gates**: an encoding view is only produced when the
  decoded bytes are overwhelmingly printable text, so a random binary blob or
  an ordinary token can never be reinterpreted into an attack.
* **Scope is preserved**: execution-tier rules still only run in execution
  context regardless of which view surfaces the evidence.
* **Deterministic**: no locale/model/network; view order is fixed.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import List
from urllib.parse import unquote_to_bytes

_A = re.ASCII

# A Base64 evidence candidate must be a whole-value, unpadded-looking token.
# 6 chars ≈ 3-4 decoded bytes: short enough to catch a small encoded amount
# ("NzUwMDA=" -> "75000", 7 chars) while staying whole-value; interception
# still requires a rule/policy to match the *decoded* text, so a benign id
# that decodes cleanly never blocks on its own.
_B64_WHOLE_RE = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$", _A)
# Minimum *decoded* length: the conservative printable gate plus the
# downstream rule/policy match carry the real false-positive protection;
# 4 decoded bytes already covers small encoded amounts ("NzUwMDA=" ->
# "75000").  Shorter tokens decode to <4 bytes and cannot form a rule hit.
_B64_MIN_DECODED = 4
# Runs of literal \xNN escape sequences (4+ bytes worth), as emitted by the
# pool's hex variant and commonly seen in shell/printf-style payloads.
_HEX_RUN_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
# Runs of percent-encoded bytes (2+ adjacent), as used in URL lexical
# disguise ("http://%6C%6F%63%61%6Chost/...").
_PERCENT_RUN_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){2,}")

# Shell token-splicing obfuscations (quote-break, no-op substitution, IFS,
# newline-broken inline comment).  Each is independently removable.
_SPLICE_NOISE = (
    "''",
    '""',
    "$(echo)",
    "$(${echo})",
)
_IFS_RE = re.compile(r"\$IFS", _A)
_COMMENT_BREAK_RE = re.compile(r"#[^\n#]*\n[ \t]*")

_MIN_PRINTABLE_RATIO = 0.90
_MAX_DECODED_BYTES = 8192


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for c in data if 9 <= c <= 13 or 32 <= c <= 126)
    return good / len(data)


def _as_text(data: bytes) -> str:
    if len(data) > _MAX_DECODED_BYTES:
        return ""
    if _printable_ratio(data) < _MIN_PRINTABLE_RATIO:
        return ""
    return data.decode("utf-8", errors="ignore")


def _nfkc_view(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value)
    return folded if folded != value else ""


def _splice_views(value: str) -> List[str]:
    views: List[str] = []
    cleaned = value
    for noise in _SPLICE_NOISE:
        cleaned = cleaned.replace(noise, "")
    cleaned = _IFS_RE.sub(" ", cleaned)
    cleaned = _COMMENT_BREAK_RE.sub(" ", cleaned)
    if cleaned != value:
        views.append(cleaned)
    return views


def _base64_views(value: str) -> List[str]:
    token = value.strip()
    if not _B64_WHOLE_RE.match(token):
        return []
    # Whole-value Base64 only; the anchored regex above already rejects
    # embedded prose and any interior whitespace.
    pad = (-len(token)) % 4
    try:
        raw = base64.b64decode(token + ("=" * pad), validate=True)
    except (binascii.Error, ValueError):
        return []
    if len(raw) < _B64_MIN_DECODED:
        return []
    text = _as_text(raw)
    return [text] if text else []


def _hex_views(value: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for m in _HEX_RUN_RE.finditer(value):
        run = m.group(0)
        if run in seen:
            continue
        seen.add(run)
        try:
            raw = bytes.fromhex(run.replace("\\x", ""))
        except ValueError:
            continue
        text = _as_text(raw)
        if text and text not in out:
            out.append(text)
    return out


def _percent_views(value: str) -> List[str]:
    # Decode every %XX triplet *in place* so the surrounding URL context is
    # preserved ("http://%6C%6F...host:9200/" -> "http://localhost:9200/").
    # Only emitted when a real encoded run (2+ adjacent triplets) exists and
    # the decoded bytes are overwhelmingly printable text.
    if not _PERCENT_RUN_RE.search(value):
        return []
    try:
        raw = unquote_to_bytes(value)
    except (ValueError, UnicodeEncodeError):
        return []
    text = _as_text(raw)
    return [text] if text and text != value else []


def candidate_views(value: str) -> List[str]:
    """Return ``[original, *evidence_views]`` for one string leaf.

    Order is fixed: original, NFKC fold, splice cleanups, whole-value Base64
    decode, literal ``\\xNN`` hex runs.  Empty/duplicate views are dropped; the
    returned list always contains the original value first.
    """
    views: List[str] = [value]
    try:
        # Cheap trigger gates first: every evidence transform is O(n) over
        # the value, so it runs only when its obfuscation signature can
        # possibly be present.  These membership tests are C-level and keep
        # adversarial padding (100k+ plain chars) at near-zero overhead.
        if not value.isascii():
            folded = _nfkc_view(value)
            if folded:
                views.append(folded)
        if ("'" in value) or ('"' in value) or ("$" in value) or ("#" in value):
            views.extend(_splice_views(value))
        if len(value) >= 6:
            views.extend(v for v in _base64_views(value) if v not in views)
        if "\\x" in value:
            views.extend(v for v in _hex_views(value) if v not in views)
        if "%" in value:
            views.extend(v for v in _percent_views(value) if v not in views)
    except Exception:
        # Normalization must never fail closed on an unexpected input shape:
        # degrade to testing the original value only.
        return [value]
    return views
