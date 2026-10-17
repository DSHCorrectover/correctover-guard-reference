"""
Semantic-aware guard rules.

The nine rules ``command-expansion`` through ``cloud-credential-path`` are a
faithful Python port of the TypeScript reference guard
(``.mcphub-work/src/middlewares/toolCallGuard.ts``).  Rule ids, ordering and
matching semantics are kept identical so existing attack/benign vectors map
1:1.  Every inspection is linear in the size of its input: potentially
catastrophic constructs are handled with a single-cursor / single-pass scan
and bounded regular expressions.

Two additional always-on rules supplement the ported set (they run *after*
the nine ported rules so ported vectors keep their original rule ids):

- ``internal-endpoint-url``: SSRF detection that understands decimal /
  hexadecimal / octal / percent-encoded IP representations of loopback,
  link-local and private-range endpoints and blocked URL schemes.
- ``credential-secret``: high-confidence secret-material formats (cloud
  access keys, PATs, JWTs, PEM private keys, ...).  Deliberately no loose
  ``password=<word>`` style matching: that form is high-noise and is left
  to the relying application.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional
from urllib.parse import unquote, urlparse

from .normalization import candidate_views

# ---------------------------------------------------------------------------
# Rule scaffolding
# ---------------------------------------------------------------------------

# Scope values mirror the TypeScript union type RuleScope.
SCOPE_ALWAYS = "always"
SCOPE_EXECUTION = "execution"

# ASCII flag everywhere: the TypeScript source matches ASCII character
# classes only, never Unicode-aware shorthands.
_A = re.ASCII


class GuardRule:
    """A single high-confidence rule.

    Attributes:
        id: stable machine-readable identifier.
        scope: ``SCOPE_ALWAYS`` (every string) or ``SCOPE_EXECUTION``
            (only values held in fields named to carry executable content).
    """

    __slots__ = ("id", "scope")

    def __init__(self, rule_id: str, scope: str):
        self.id = rule_id
        self.scope = scope

    def test(self, value: str) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<GuardRule %s scope=%s>" % (self.id, self.scope)


# ---------------------------------------------------------------------------
# Execution-key classification
# ---------------------------------------------------------------------------

EXECUTION_KEYS = frozenset({
    "command",
    "cmd",
    "cmds",
    "script",
    "exec",
    "execute",
    "shell",
    "run",
    "code",
    "statement",
    "expression",
})

EXECUTION_KEY_SUFFIXES = ("command", "commands", "script")

_NORMALIZE_RE = re.compile(r"[_\-\s]", _A)


def is_execution_key(key: str) -> bool:
    """True when an object key is explicitly named to carry a command.

    Mirrors ``isExecutionKey``: lower-case the key, strip ``_``/``-``/space,
    then match the exact set or one of the suffixes.
    """
    normalised = _NORMALIZE_RE.sub("", key.lower())
    if normalised in EXECUTION_KEYS:
        return True
    return any(normalised.endswith(suffix) for suffix in EXECUTION_KEY_SUFFIXES)


# ---------------------------------------------------------------------------
# Ported rules
# ---------------------------------------------------------------------------

# command-expansion
_COMMAND_SUBST_RE = re.compile(r"\$\([^)]", _A)
_SHELL_SYNTAX_CHARS_RE = re.compile(r"[;&|$/]", _A)
_COMMAND_IN_BACKTICK_RE = re.compile(
    r"^\s*(?:sudo\s+)?(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|python"
    r"|perl|ruby|chmod|chown|rm|cp|mv)(?:\s+\S|\s*$)",
    _A,
)


def _backtick_span_contains(value: str) -> bool:
    """Linear scan of backtick-delimited spans for shell syntax/commands."""
    open_pos = -1
    for i, ch in enumerate(value):
        if ch != "`":
            continue
        if open_pos == -1:
            open_pos = i
        else:
            span = value[open_pos + 1:i]
            if (_SHELL_SYNTAX_CHARS_RE.search(span)
                    or _COMMAND_IN_BACKTICK_RE.match(span)):
                return True
            open_pos = -1
    return False


class CommandExpansionRule(GuardRule):
    def __init__(self):
        super().__init__("command-expansion", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        return bool(_COMMAND_SUBST_RE.search(value)) or _backtick_span_contains(value)


# shell-chaining
_SHELL_CHAINING_RE = re.compile(
    r"(?:;|&&|\|\|)\s*(?:sudo\s+)?(?:cat|ls|id|whoami|uname|wget|curl|bash"
    r"|sh|nc|python|perl|ruby|chmod|chown|rm|cp|mv)\b",
    _A,
)


class ShellChainingRule(GuardRule):
    def __init__(self):
        super().__init__("shell-chaining", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        return bool(_SHELL_CHAINING_RE.search(value))


# downloader-pipe
_SH_C_CURL_RE = re.compile(
    r"(?:ba|z|fi|k|t?c)?sh\s+-c\s+[\"']?\$\((?:curl|wget)\b", _A
)
_SHELL_AFTER_PIPE_RE = re.compile(r"^(?:sudo\s+)?(?:ba|z|fi|k|t?c)?sh\b", _A)
_DOWNLOADER_IN_SEGMENT_RE = re.compile(r"\b(?:curl|wget)\b", _A)


def _has_downloader_piped_to_shell(line: str) -> bool:
    # Fast C-level pre-check: a piped form needs a pipe and a downloader.
    if "|" not in line or ("curl" not in line and "wget" not in line):
        return False
    downloader_seen = False
    for segment in line.split("|"):
        if (downloader_seen
                and _SHELL_AFTER_PIPE_RE.match(segment.lstrip())):
            return True
        if _DOWNLOADER_IN_SEGMENT_RE.search(segment):
            downloader_seen = True
    return False


class DownloaderPipeRule(GuardRule):
    def __init__(self):
        super().__init__("downloader-pipe", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        if _SH_C_CURL_RE.search(value):
            return True
        for line in value.split("\n"):
            if _has_downloader_piped_to_shell(line):
                return True
        return False


# sensitive-file-read
_SHADOW_PATH_RE = re.compile(r"/etc/shadow(?![\w.-])", _A)
_PASSWD_TOKEN_RE = re.compile(r"/etc/passwd(?![\w.-])$", _A)

FILE_READER_WORDS = frozenset({
    "cat", "head", "tail", "less", "more", "tac", "nl",
    "od", "xxd", "cp", "mv", "grep", "open",
})


def _strip_quotes(token: str) -> str:
    if len(token) < 2:
        return token
    first = token[0]
    last = token[-1]
    if (first == '"' or first == "'") and last == first:
        return token[1:-1]
    return token


def _is_passwd_token(token: str) -> bool:
    return bool(_PASSWD_TOKEN_RE.search(_strip_quotes(token)))


def _is_file_reader_token(token: str) -> bool:
    slash = token.rfind("/")
    name = token if slash == -1 else token[slash + 1:]
    return name in FILE_READER_WORDS


def _has_reader_then_passwd(line: str) -> bool:
    reader_seen = False
    for token in re.split(r"\s+", line):
        if _is_passwd_token(token) and reader_seen:
            return True
        if _is_file_reader_token(token):
            reader_seen = True
    return False


class SensitiveFileReadRule(GuardRule):
    def __init__(self):
        super().__init__("sensitive-file-read", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        for line in value.split("\n"):
            if _SHADOW_PATH_RE.search(line):
                return True
            if _has_reader_then_passwd(line):
                return True
        return False


# force-delete-root
_RM_WORD_RE = re.compile(r"\brm\b", _A)
_ROOT_TARGET_RE = re.compile(r"(?:--no-preserve-root\b)?\s/(?:\s|$|\*)", _A)


def _has_recursive_force_flag(line: str) -> bool:
    if "--no-preserve-root" in line:
        return True
    for token in re.split(r"\s+", line):
        if len(token) < 2 or token[0] != "-" or token[1] == "-":
            continue
        if "r" in token[1:]:
            return True
    return False


class ForceDeleteRootRule(GuardRule):
    def __init__(self):
        super().__init__("force-delete-root", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        for line in value.split("\n"):
            if not _RM_WORD_RE.search(line):
                continue
            if not _has_recursive_force_flag(line):
                continue
            if _ROOT_TARGET_RE.search(line):
                return True
        return False


# chmod dangerous permission grant: world-writable (0002 o+w style 777/666)
# or setuid/setgid bit (leading 4/2, e.g. 4755) on any path.  Execution
# scope only; the mode itself is the high-confidence signal.
_CHMOD_WORD_RE = re.compile(r"\bchmod\b", _A)
_CHMOD_MODE_RE = re.compile(
    r"(?:^|[\s=])(?:"
    r"[0-7]?[67][0-7][0-7]"        # octal 666/777-family, optional special bit
    r"|[24][0-7]{3}"               # setgid (2xxx) / setuid (4xxx)
    r"|[augo]*[+-=]?s\b"           # symbolic s bit
    r")"
)


class ChmodDangerRule(GuardRule):
    def __init__(self):
        super().__init__("chmod-danger", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        for line in value.split("\n"):
            if not _CHMOD_WORD_RE.search(line):
                continue
            if _CHMOD_MODE_RE.search(line):
                return True
        return False


# reverse-shell
_BASH_INTERACTIVE_RE = re.compile(r"bash\s+-i\b", _A)
_NETCAT_WORD_RE = re.compile(r"\bnc(?:at)?\b", _A)
_NETCAT_EXEC_RE = re.compile(
    r"(?:^|\s)-e\s+/(?:bin|usr/bin)/sh(?![\w.-])", _A
)

_DEV_TCP_PREFIX = "/dev/tcp/"
_WHITESPACE_RE = re.compile(r"\s", _A)
_DIGITS_RE = re.compile(r"^\d+$", _A)


def _has_dev_tcp_redirect(value: str) -> bool:
    cursor = 0
    length = len(value)
    while True:
        start = value.find(_DEV_TCP_PREFIX, cursor)
        if start == -1:
            return False
        rest_start = start + len(_DEV_TCP_PREFIX)
        end = rest_start
        while end < length and not _WHITESPACE_RE.match(value[end]):
            end += 1
        segment = value[rest_start:end]
        slash = segment.rfind("/")
        if slash != -1 and _DIGITS_RE.match(segment[slash + 1:]):
            return True
        cursor = end


def _has_netcat_exec_shell(line: str) -> bool:
    if not _NETCAT_WORD_RE.search(line):
        return False
    return bool(_NETCAT_EXEC_RE.search(line))


class ReverseShellRule(GuardRule):
    def __init__(self):
        super().__init__("reverse-shell", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        if _has_dev_tcp_redirect(value):
            return True
        if _BASH_INTERACTIVE_RE.search(value):
            return True
        for line in value.split("\n"):
            if _has_netcat_exec_shell(line):
                return True
        return False


# powershell-cradle
_PS_DOWNLOAD_RE = re.compile(
    r"(?:downloadstring|downloadfile|invoke-webrequest\s*\(|"
    r"invoke-restmethod\s*\(|\biwr\b|\birm\b)", _A
)
_PS_EXECUTE_RE = re.compile(r"(?:iex|invoke-expression)\s*[.(]", _A)


class PowerShellCradleRule(GuardRule):
    def __init__(self):
        super().__init__("powershell-cradle", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        lower = value.lower()
        # Both halves are required; pre-check a cheap marker before regex.
        if not any(marker in lower for marker in ("iex", "invoke-expression")):
            return False
        return bool(_PS_DOWNLOAD_RE.search(lower)) and bool(_PS_EXECUTE_RE.search(lower))


# cloud-metadata-url
_CLOUD_METADATA_URL_RE = re.compile(
    r"https?://(?:169\.254\.169\.254|2852039166|0xa9fea9fe)(?::\d+)?/", _A
)
_CLOUD_METADATA_HOST_RE = re.compile(
    r"https?://(?:metadata\.google\.internal"
    r"|169\.254\.169\.254\.metadata\.azure\.com"
    r"|100\.100\.100\.200)/",
    _A,
)


class CloudMetadataUrlRule(GuardRule):
    def __init__(self):
        super().__init__("cloud-metadata-url", SCOPE_ALWAYS)

    def test(self, value: str) -> bool:
        return bool(_CLOUD_METADATA_URL_RE.search(value)
                    or _CLOUD_METADATA_HOST_RE.search(value))


# cloud-credential-path
_CLOUD_CREDENTIAL_PATH_RE = re.compile(
    r"/latest/(?:meta-data|api/token)", _A
)
_COMPUTE_METADATA_RE = re.compile(r"/computeMetadata/v1/", _A)
_METADATA_INSTANCE_RE = re.compile(r"/metadata/instance/", _A)
_CLOUD_CREDENTIAL_HOST_RE = re.compile(
    r"(?:metadata\.aliyuninc\.com|169\.254\.170\.2)/", _A
)


class CloudCredentialPathRule(GuardRule):
    def __init__(self):
        super().__init__("cloud-credential-path", SCOPE_ALWAYS)

    def test(self, value: str) -> bool:
        return bool(
            _CLOUD_CREDENTIAL_PATH_RE.search(value)
            or _COMPUTE_METADATA_RE.search(value)
            or _METADATA_INSTANCE_RE.search(value)
            or _CLOUD_CREDENTIAL_HOST_RE.search(value)
        )


# ---------------------------------------------------------------------------
# Supplementary: SSRF with IP-encoding bypass awareness
# ---------------------------------------------------------------------------

_BLOCKED_SCHEMES = frozenset({
    "file", "gopher", "dict", "ftp", "tftp",
    "jar", "netdoc", "nfs", "smb",
})

# Find URL-like tokens anywhere in a string.  The scheme alternation is
# bounded and the remainder run is linear; it never backtracks over nested
# quantifiers.
_URL_TOKEN_RE = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.\-]{0,15}://[^\s'\"<>)]{1,2048}", _A
)


def _is_internal_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return bool(addr.is_private or addr.is_loopback
                or addr.is_link_local or addr.is_reserved
                or addr.is_unspecified)


def _decode_ip_variants(host: str) -> List[str]:
    """Expand a host into candidate IP representations (SSRF bypass forms)."""
    candidates = [host]
    decoded = unquote(host)
    if decoded != host:
        candidates.append(decoded)
    # Decimal: 2130706433 -> 127.0.0.1
    try:
        candidates.append(str(ipaddress.IPv4Address(int(host))))
    except (ValueError, TypeError):
        pass
    # Hexadecimal: 0x7f000001
    if host[:2] in ("0x", "0X"):
        try:
            candidates.append(str(ipaddress.IPv4Address(int(host, 16))))
        except (ValueError, TypeError):
            pass
    # Dotted octal: 0177.0.0.1
    if "." in host:
        parts = host.split(".")
        if all(len(p) > 0 for p in parts) and any(
            p[0] == "0" and len(p) > 1 for p in parts
        ):
            try:
                octets = [int(p, 8) for p in parts]
                if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                    candidates.append(".".join(str(o) for o in octets))
            except (ValueError, TypeError):
                pass
    return candidates


_LOCALHOST_NAMES = frozenset({"localhost", "localhost.localdomain",
                              "ip6-localhost", "ip6-loopback"})


def _host_is_internal(host: str) -> bool:
    host = host.strip().lower()
    if not host:
        return False
    if host in _LOCALHOST_NAMES:
        return True
    # ``urlparse.hostname`` removes IPv6 brackets; keep a wrapper check too
    # for callers that pass a raw bracketed literal.
    if host[0] == "[" and host[-1] == "]":
        host = host[1:-1]
    for variant in _decode_ip_variants(host):
        if _is_internal_ip(variant):
            return True
    return False


def _url_is_internal(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    scheme = (parsed.scheme or "").lower()
    if scheme in _BLOCKED_SCHEMES:
        return True
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False
    if _host_is_internal(hostname):
        return True
    # @-trick / DNS-rebinding style: the real destination is after the last @
    if parsed.netloc and "@" in parsed.netloc:
        after_at = parsed.netloc.rsplit("@", 1)[-1]
        if _host_is_internal(after_at.split(":")[0]):
            return True
    return False


class InternalEndpointUrlRule(GuardRule):
    """SSRF: block URLs targeting internal endpoints, incl. encoded IPs."""

    def __init__(self):
        super().__init__("internal-endpoint-url", SCOPE_ALWAYS)

    def test(self, value: str) -> bool:
        for match in _URL_TOKEN_RE.finditer(value):
            if _url_is_internal(match.group(0)):
                return True
        return False


# ---------------------------------------------------------------------------
# Supplementary: high-confidence secret material
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----", _A),
    re.compile(r"AKIA[0-9A-Z]{16}", _A),
    re.compile(r"ASIA[0-9A-Z]{16}", _A),
    re.compile(r"ghp_[A-Za-z0-9]{20,}", _A),
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}", _A),
    re.compile(r"sk-[A-Za-z0-9]{20,}", _A),
    re.compile(r"AIza[A-Za-z0-9_\-]{35}", _A),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]+", _A),
    re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}", _A),
    re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+", _A
    ),
)


class CredentialSecretRule(GuardRule):
    """High-confidence embedded secret formats."""

    def __init__(self):
        super().__init__("credential-secret", SCOPE_ALWAYS)

    def test(self, value: str) -> bool:
        for pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                return True
        return False


# destructive-sql (high-confidence catastrophic SQL; execution scope)
_SQL_DROP_RE = re.compile(
    r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", _A | re.IGNORECASE
)
_SQL_TRUNCATE_RE = re.compile(r"\bTRUNCATE\s+TABLE\b", _A | re.IGNORECASE)
# DELETE / UPDATE without a WHERE in the same statement = full-table wipe.
_SQL_DELETE_RE = re.compile(r"\bDELETE\s+FROM\b", _A | re.IGNORECASE)
_SQL_UPDATE_RE = re.compile(r"\bUPDATE\b[\s\S]*?\bSET\b", _A | re.IGNORECASE)
_SQL_WHERE_RE = re.compile(r"\bWHERE\b", _A | re.IGNORECASE)


class DestructiveSqlRule(GuardRule):
    """Catastrophic SQL: DROP/TRUNCATE or WHERE-less DELETE/UPDATE.

    Execution scope: only evaluated beneath fields named to carry executable
    content (``statement``/``query``/``command``/...), so ordinary prose that
    merely mentions the words is not matched.
    """

    def __init__(self):
        super().__init__("destructive-sql", SCOPE_EXECUTION)

    def test(self, value: str) -> bool:
        if _SQL_DROP_RE.search(value) or _SQL_TRUNCATE_RE.search(value):
            return True
        if _SQL_DELETE_RE.search(value) or _SQL_UPDATE_RE.search(value):
            return not _SQL_WHERE_RE.search(value)
        return False


# ---------------------------------------------------------------------------
# Rule registry — ported nine first, supplements after
# ---------------------------------------------------------------------------

def default_rules() -> List[GuardRule]:
    """Return a fresh ordered rule list (ported rules first)."""
    return [
        CommandExpansionRule(),
        ShellChainingRule(),
        DownloaderPipeRule(),
        SensitiveFileReadRule(),
        ForceDeleteRootRule(),
        ChmodDangerRule(),
        ReverseShellRule(),
        PowerShellCradleRule(),
        CloudMetadataUrlRule(),
        CloudCredentialPathRule(),
        InternalEndpointUrlRule(),
        CredentialSecretRule(),
        DestructiveSqlRule(),
    ]


SCAN_LIMIT_RULE_ID = "scan-limit-exceeded"
MAX_SCAN_BYTES = 1_000_000


def inspect_tool_arguments(
    args: object,
    rules: Optional[List[GuardRule]] = None,
    max_scan_bytes: int = MAX_SCAN_BYTES,
) -> Optional[str]:
    """Inspect tool arguments; return the first firing rule id, else ``None``.

    Mirrors ``inspectToolArguments``: a single decrementing character budget
    shared across the whole traversal, always-on rules for every string and
    execution-tier rules only beneath execution-named keys.  A string that
    cannot be fully inspected inside the remaining budget returns the
    ``scan-limit-exceeded`` rule id (fail-closed).
    """
    active_rules = rules if rules is not None else default_rules()
    budget = max_scan_bytes

    def scan(node: object, execution: bool) -> Optional[str]:
        nonlocal budget
        if isinstance(node, str):
            if len(node) > budget:
                return SCAN_LIMIT_RULE_ID
            budget -= len(node)
            # Pass 1: original value, every in-scope rule (order preserved,
            # benign large inputs stay single-pass).
            for rule in active_rules:
                if rule.scope == SCOPE_EXECUTION and not execution:
                    continue
                if rule.test(node):
                    return rule.id
            # Pass 2: bounded evidence views for encoded/spliced payloads.
            extra_views = candidate_views(node)[1:]
            for view in extra_views:
                if len(view) > budget:
                    return SCAN_LIMIT_RULE_ID
                budget -= len(view)
            if extra_views:
                for rule in active_rules:
                    if rule.scope == SCOPE_EXECUTION and not execution:
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
                hit = scan(value, execution or is_execution_key(str(key)))
                if hit:
                    return hit
        return None

    return scan(args, False)
