# Figure W4-1 — caption (paper draft)

**Figure W4-1. Guard verdict behaviour across the G-G escape-variant matrix,
before and after the evidence-view normalization tier.**
Two paired four-panel evaluations of the Correctover Guard reference
implementation against the **same byte-frozen `dev` split** of the G-G
parameter-risk vector pool (200 attack vectors across five parameter classes
and 16 risk families; 200 benign vectors drawn from 229,539 live MCP tool
schemas). The pool is byte-frozen and individually SHA-256 addressed
(`dev.jsonl` SHA-256
`77d533612cb19c5894a2b037628eeff3bc0745276abe5a729a90387223d31bb3`); the only
change between the two figures is the guard binary (pre-normalization build vs.
build with the evidence-view tier), so the paired panels isolate the tier's
effect on an identical corpus. Coloured points are individual vectors
(blue = command-string, amber = url-endpoint, red = credential-value; grey
triangles in B = benign); black lines are binned medians (A, C) or per-group
means (B, D).

Overall attack interception rises from **35.5% to 95.0%** on the identical 200
attack vectors, with false positives remaining **0/200 in both runs**.

- **(A)** Verdict latency stays flat across payload lengths from 8 to ≈300
  bytes (log-scaled): P50 ≈327 µs, in-process routing scope. The normalization
  tier adds no measurable median cost: benign large inputs run a single pass
  over the original value and evidence views are generated only when the first
  pass misses, gated by cheap per-encoding feature triggers.
- **(B)** Interception by escape variant. Before the tier, whole-value
  obfuscations — Base64, hex, NFKC homoglyphs — pass almost unimpeded while
  plaintext is caught; after the tier, all six variants are blocked at
  **94% (plain), 92% (base64), 95% (hex), 95% (nfkc), 98% (split), 100%
  (lexical)**. Decoding never rewrites the original parameters: candidate
  evidence views are tested read-only, policy and receipt hashing stay on the
  raw values, and a rule may fire only on a decoded view whose result matches a
  real danger rule, which keeps the FPR at zero.
- **(C)** Encodings inflate payload length by 2–3× (Base64/hex medians
  ≈85–125 bytes vs ≈32 bytes plaintext) — unchanged, as expected; length is an
  input property, not a guard property.
- **(D)** Family-level interception. Structurally explicit families (cloud
  metadata URLs, credential exfiltration, money bounds) were already at or near
  100% and remain there; the shell-value families that collapsed under
  encoding (downloader pipes, reverse shells, destructive SQL, `chmod`,
  sensitive file reads) are lifted to the same plateau. The single family that
  remains below the plateau is ordinary-field smuggling: its residual misses
  are shell syntax placed in non-execution free-text fields (`name`, `data`,
  `content`). Execution-scoped danger rules are deliberately tested only on
  execution-bearing fields (or fields the schema annotates as command
  strings); identical smuggling in a declared command field (e.g. `query`) is
  blocked at 100%. This is an explicit scope boundary taken to protect the
  0/200 false-positive rate, not a detector defect, and is reported as an
  out-of-scope residual rather than tuned away.

*Reproducibility.* Both runs are recorded under `eval/runs/`
(pre: `dev-20261017-103227`; post: `dev-20261017-112602`) against the same
`dev.jsonl`. Figures: `figure-w4-1-dev-baseline-pre.{png,pdf}` and
`figure-w4-1-dev-baseline-post.{png,pdf}`. The `holdout` split (including
`chmod 777 /etc/passwd` and `DELETE FROM users WHERE` families) remains sealed
and was not consulted during this iteration.
