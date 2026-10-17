# Correctover Guard — open reference layer & G-G Parameter-Risk Pool

<https://github.com/DSHCorrectover/correctover-guard-reference>


An **independent, fail-closed philosophy** for verifying AI-agent tool calls,
and a **byte-frozen, third-party-reproducible benchmark** for the case plaintext
scanners miss: parameter-level attacks hidden by encoding or lexical
obfuscation (Base64, hex escapes, NFKC homoglyphs, quote/`$IFS` splitting,
scientific/percent/trailing-dot lexical tricks).

This repository pairs the exact rule/normalization logic with the frozen
vectors, so anyone can reproduce the headline result from scratch:

> **On the same 200-attack / 200-benign frozen `dev` pool, adding the
> evidence-view normalization tier raises attack interception from 35.5% to
> 95.0%, with 0/200 false positives in both runs.**

## What is here

| Path | What it is |
| --- | --- |
| `correctover_guard_ref/rules.py` | danger-rule surface + execution-scope taxonomy |
| `correctover_guard_ref/normalization.py` | read-only evidence-view tier (NFKC / shell-splice / Base64 / `\xHH` / `%XX`) |
| `correctover_guard_ref/risk_profile.py` | static tool-schema → G-G parameter labels |
| `correctover_guard_ref/risk_router.py` | policy evaluation + value-rule scan with the schema-widened execution tier |
| `correctover_guard_ref/reference_guard.py` | tiny in-process adjudicator wiring the chain above |
| `eval/vector-pool/dev.jsonl` | **400 published vectors** (200 attack / 200 benign), byte-frozen |
| `eval/vector-pool/smoke.jsonl` | 16-vector CI smoke split |
| `eval/runs/` | the paired pre/post records (`103227` = 35.5%, `112602` = 95.0%) |
| `eval/figures/` | the four-panel pre/post figures + caption |
| `eval/scripts/` | deterministic generator, evaluator and plotting script |

## The core idea: evidence views, never rewriting input

The guard **never decodes or mutates the raw parameters** (the receipt hash and
operator policy are always evaluated on the originals). For each string leaf it
first runs every in-scope rule against the original value; only if that misses
does it generate bounded, read-only **candidate evidence views** and re-run the
rules:

- NFKC compatibility fold (full-width `ｒｍ －ｒｆ` → `rm -rf`)
- shell splice cleaning (`"a";cmd` / `$IFS` / comment-newline / `$(echo)` concat)
- whole-value Base64, `\xHH` hex runs, and `%XX` percent-decoding

A decoded view fires **only** when it matches a real danger rule, and every
decoder is gated by a cheap feature trigger plus a printability/length guard —
which is how the extra tier keeps the false-positive rate at **0/200**.

### Execution scope (why the last 10 attacks are honestly missed)

Shell-oriented rules run only on execution-bearing keys or fields the schema
labels `gg:command-string` (e.g. `query`). They deliberately do **not** run over
ordinary free-text fields (`name`, `data`, `content`). The 10 residual misses
are shell syntax smuggled into exactly those non-execution fields; the same
payload in a declared command field is blocked. This is an explicit trade to
protect the 0/200 FPR, reported as an out-of-scope residual rather than tuned
away (see `eval/figures/figure-w4-1-caption.md`).

## Reproduce

```bash
# standard library only for the guard + evaluator (matplotlib/numpy for the plot)
python eval/scripts/eval_vector_pool.py dev
python eval/scripts/eval_vector_pool.py smoke

# regenerate the figure from a run record
python eval/scripts/plot_w4_figure.py eval/runs/dev-20261017-112602.json post
python eval/scripts/plot_w4_figure.py eval/runs/dev-20261017-103227.json pre
```

The evaluator first asserts each split's SHA-256 against `manifest.json`, so a
reproduced run cannot silently differ from the published pool.

- `dev.jsonl` SHA-256 `77d533612cb19c5894a2b037628eeff3bc0745276abe5a729a90387223d31bb3`
- `smoke.jsonl` SHA-256 `5551a43f09318a3b2ae310ee8a86675998eff808a24b15a74cd950000683be08`

### Results

| | pre-normalization | post-normalization |
| --- | --- | --- |
| attack interception | 35.5% | **95.0%** |
| false positives | 0/200 | **0/200** |

By variant after the tier: plain 94.4%, Base64 92.1%, hex 94.7%, NFKC 94.6%,
split 97.6%, lexical 100%. Command / credential / money / url attack buckets:
100% each.

**Latency scope — two different numbers, both honest.** The archived run JSONs
in `eval/runs/` were produced by the production binary's *in-process* mode,
which also builds and Ed25519-signs a per-call receipt (post P50 ≈ 327 µs). If
you re-run the evaluator in this repository, the open `ReferenceGuard` performs
the **same adjudication** — every verdict, and therefore the 95.0% / 0-FPR
result, is identical — but it does not build or sign a receipt, so its measured
P50 is much lower (≈ 33 µs). The difference is the excluded signing core, not a
faster rule engine. Neither number is the production **fail-closed cross-process
path** (independent verifier over IPC + pinned Ed25519 trust root, ≈ 379 µs);
the three scopes must not be conflated.

## License (two layers)

- **Code** — Elastic License 2.0 (`LICENSE`). You may use it, but you may not
  offer it to third parties as a hosted/managed service exposing a substantial
  part of its functionality.
- **Dataset, runs, figures** — CC-BY-SA-4.0 (`DATA-LICENSE`): reuse with
  attribution; adapted vector sets must stay under the same ShareAlike terms.

## What is deliberately NOT here

The independent cross-process **fail-closed verifier**, the pinned **Ed25519
trust root**, the **signed adjudication-receipt kernel** and the fail-closed IPC
transport are proprietary and are not published. What is open is the
verification *standard* and this in-process *reference*. See `STANDARD.md`.

A **200-vector holdout split exists but is sealed and not distributed**; it is
used for a single post-freeze, no-tuning confirmation and was never consulted
while these rules were developed. The 229,539 live-MCP schema rows used to
derive benign parameters are third-party static-schema content and are not
redistributed.

## Author & citation

Guigui Wang (Correctover), *G-G Parameter-Risk Pool*, v1.0.0, 2026-10-17.
Please cite this repository and the archived Zenodo release
([10.5281/zenodo.23430965](https://doi.org/10.5281/zenodo.23430965); concept
record: [10.5281/zenodo.23430964](https://doi.org/10.5281/zenodo.23430964))
when you use the pool or the evidence-view design. This is an individual
submission; it is not an RFC and carries no IETF endorsement.
