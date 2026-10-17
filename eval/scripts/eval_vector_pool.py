#!/usr/bin/env python3
"""W4 vector-pool evaluator: smoke / dev / holdout, full metric suite.

The frozen JSONL stores ONLY the 11 auditable fields. Everything the engine
needs (params, JSON schema, operator policy) is rebuilt DETERMINISTICALLY from
those fields, so a third party can reproduce every verdict from the frozen
file alone plus the open in-process reference guard code:

  params = {field: payload} (+ the credential-exfiltration cross field)
  schema = object{field: string(CLASS_DESC[gg_class])} (+ cross prop)
  policy = family -> explicit money bound / exfil block / default-warn

Usage:
  python scripts/eval_vector_pool.py smoke          # CI regression, 16
  python scripts/eval_vector_pool.py dev            # iteration metrics, 400
  python scripts/eval_vector_pool.py holdout        # GATED: refuses
  python scripts/eval_vector_pool.py holdout --release   # one official run

Holdout is ledger-gated: exactly one official run is recorded; it refuses
before the rules freeze and refuses again afterwards until an operator
manually rotates eval/runs/holdout-ledger.json.

Scope: frozen G-G-paradigm SELF-evaluation, not a public benchmark. External
citation requires a third-party runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import time
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from correctover_guard_ref import ReferenceGuard, PolicyProfile  # noqa: E402
from correctover_guard_ref import profile_tool_schema  # noqa: E402

POOL_DIR = os.path.join(ROOT, "eval", "vector-pool")
RUN_DIR = os.path.join(ROOT, "eval", "runs")
LEDGER = os.path.join(RUN_DIR, "holdout-ledger.json")

# mirrors build_vector_pool.py (reconstruction contract)
CLASS_DESC = {
    "command": "shell command / instruction parameter",
    "url": "endpoint URL parameter",
    "credential": "secret token credential parameter",
    "money": "amount in cents parameter",
    "filesystem": "destination file path parameter",
    "ordinary": "",
}
CANON_LABEL = {
    "command": "gg:command-string",
    "url": "gg:url-endpoint",
    "credential": "gg:credential-value",
    "money": "gg:money-amount",
    "filesystem": "gg:filesystem-path",
}
HEADLINE_BUCKET = {
    "command": "command", "url": "url", "credential": "credential",
    "money": "money", "filesystem": "ordinary", "ordinary": "ordinary",
}
VARIANT_ORDER = {"plain": 0, "base64": 1, "hex": 2, "nfkc": 3,
                 "split": 4, "lexical": 5}
# exfil cross-field vectors, keyed by split (the only cross-field family)
EXFIL_CROSS = {
    "dev": ("webhook_url", "callback endpoint URL",
            "https://collector.example.net/ingest"),
    "holdout": ("callback_url", "callback endpoint URL",
                "https://exfil.example.com/drop"),
}
LOCKED_PAYLOADS = {"chmod 777 /etc/passwd", "DELETE FROM users WHERE"}

FROZEN_FIELDS = (
    "payload", "gg_class", "family", "variant", "expected_verdict",
    "expected_rule_hint", "field", "tool", "source", "split")


def pct(n, d):
    return 100.0 * n / d if d else 0.0


def pct_s(n, d):
    return "%.1f%%" % pct(n, d) if d else "n/a"


def percentile(xs, q):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    if lo == hi:
        return xs[lo]
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


# ---------------------------------------------------------------------------
# frozen-file loading + deterministic reconstruction
# ---------------------------------------------------------------------------

def load_split(name):
    path = os.path.join(POOL_DIR, "%s.jsonl" % name)
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    manifest = json.load(open(os.path.join(POOL_DIR, "manifest.json"),
                              encoding="utf-8"))
    want = manifest["splits"][name]["sha256_file"]
    got = hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert got == want, "frozen hash mismatch for %s" % name
    for r in rows:
        body = json.dumps({k: r[k] for k in FROZEN_FIELDS},
                          sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")).encode()
        assert hashlib.sha256(body).hexdigest() == r["sha256"], \
            "vector hash mismatch: %s" % r.get("field")
        rebuild(r)
    return rows, manifest


def rebuild(v):
    """Attach params/schema/policy derived solely from the 11 frozen fields."""
    gg = v["gg_class"]
    field = v["field"]
    params = {field: v["payload"]}
    props = {field: {"type": "string", "description": CLASS_DESC.get(gg, "")}}
    policy = {"money_limits": {}, "credential_exfil": "warn",
              "strict_missing_schema": False}

    if v["family"] == "credential-exfiltration":
        xf, xdesc, xval = EXFIL_CROSS[v["split"]]
        params[xf] = xval
        props[xf] = {"type": "string", "description": xdesc}
        policy["credential_exfil"] = "block"
    elif v["family"] == "money-bound":
        policy["money_limits"] = {field: 50000}

    v["params"] = params
    v["schema"] = {"type": "object", "properties": props}
    v["policy"] = policy
    v["locked"] = (v["split"] == "holdout"
                   and v["payload"] in LOCKED_PAYLOADS)
    v["headline_bucket"] = HEADLINE_BUCKET[gg]


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------

def evaluate(rows):
    guards = {}

    def get_guard(pol):
        key = json.dumps(pol, sort_keys=True)
        if key not in guards:
            guards[key] = ReferenceGuard(policy=PolicyProfile(**pol))
        return guards[key]

    n_attack = n_benign = blocked = 0
    fn_cases, fp_cases, schema_mismatch = [], [], []
    per_bucket = defaultdict(lambda: {"attack": 0, "blocked": 0,
                                      "benign": 0, "fp": 0})
    miss = defaultdict(int)          # (family, variant) FN
    fam_total = defaultdict(int)
    var_total = defaultdict(int)
    var_block = defaultdict(int)
    rule_hits = defaultdict(int)
    lat_all = []
    lat_bucket = defaultdict(list)
    points = []                     # per-vector records for the figure/JSON

    for v in rows:
        g = get_guard(v["policy"])

        # schema-conformance: rebuilt schema must profile to the frozen label
        prof = profile_tool_schema(v["tool"], v["schema"])
        want = CANON_LABEL.get(v["gg_class"])
        got = set(prof.labels_by_tool)
        if want is None and got:
            schema_mismatch.append((v["field"], v["gg_class"], sorted(got)))
        elif want is not None and want not in got:
            schema_mismatch.append((v["field"], v["gg_class"], sorted(got)))

        bucket = v["headline_bucket"]
        t0 = time.perf_counter()
        d = g.check(tool=v["tool"], params=v["params"], schema=v["schema"])
        dt = (time.perf_counter() - t0) * 1_000_000.0
        lat_all.append(dt)
        lat_bucket[bucket].append(dt)

        is_attack = v["expected_verdict"] == "deny"
        pb = per_bucket[bucket]
        if is_attack:
            n_attack += 1
            pb["attack"] += 1
            fam_total[v["family"]] += 1
            var_total[v["variant"]] += 1
            if not d.allowed:
                blocked += 1
                pb["blocked"] += 1
                var_block[v["variant"]] += 1
                rule_hits[d.rule_id or "(none)"] += 1
            else:
                fn_cases.append({
                    "family": v["family"], "variant": v["variant"],
                    "gg_class": v["gg_class"],
                    "payload": v["payload"][:70],
                    "locked": v["locked"]})
                miss[(v["family"], v["variant"])] += 1
        else:
            n_benign += 1
            pb["benign"] += 1
            if not d.allowed:
                fp_cases.append({"family": v["family"],
                                 "gg_class": v["gg_class"],
                                 "payload": v["payload"][:70],
                                 "rule": d.rule_id})
                pb["fp"] += 1

        points.append({
            "payload_len": len(v["payload"].encode("utf-8", "replace")),
            "latency_us": dt,
            "blocked": (not d.allowed) if is_attack else None,
            "verdict_deny": not d.allowed,
            "expected_deny": is_attack,
            "variant": v["variant"],
            "variant_rank": VARIANT_ORDER[v["variant"]],
            "family": v["family"],
            "gg_class": v["gg_class"],
            "bucket": bucket,
            "rule": d.rule_id,
            "locked": v["locked"],
        })

    out = {
        "n_attack": n_attack,
        "n_benign": n_benign,
        "blocked": blocked,
        "interception": pct(blocked, n_attack),
        "fpr": pct(len(fp_cases), n_benign),
        "fnr": pct(len(fn_cases), n_attack),
        "fp": fp_cases,
        "fn": fn_cases,
        "schema_mismatch": schema_mismatch,
        "per_bucket": {},
        "per_variant": {
            k: {"total": var_total[k], "blocked": var_block[k],
                "interception": pct(var_block[k], var_total[k])}
            for k in sorted(var_total, key=lambda x: VARIANT_ORDER[x])},
        "rule_hits": dict(sorted(rule_hits.items())),
        "miss_matrix": {
            "%s|%s" % k: {"fn": c, "family_total": fam_total[k[0]]}
            for k, c in sorted(miss.items())},
        "latency_us": {
            "p50": percentile(lat_all, .5),
            "p95": percentile(lat_all, .95),
            "p99": percentile(lat_all, .99),
            "mean": statistics.mean(lat_all),
            "max": max(lat_all),
            "scope": "OPEN in-process reference guard (policy + schema-widened "
                     "rules + evidence views; no cross-process verifier, no "
                     "signed receipt)",
            "per_bucket": {b: {
                "p50": percentile(xs, .5), "p95": percentile(xs, .95),
                "p99": percentile(xs, .99), "n": len(xs)}
                for b, xs in sorted(lat_bucket.items())},
        },
        "points": points,
    }
    for b, pb in sorted(per_bucket.items()):
        out["per_bucket"][b] = {
            "attack": pb["attack"], "blocked": pb["blocked"],
            "benign": pb["benign"], "fp": pb["fp"],
            "interception": pct(pb["blocked"], pb["attack"]),
            "fpr": pct(pb["fp"], pb["benign"]),
            "fnr": pct(pb["attack"] - pb["blocked"], pb["attack"])
            if pb["attack"] else 0.0}
    return out


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def render_text(name, res):
    L = ["=" * 74,
         "W4 G-G vector-pool eval   split=%s   (frozen file, hash-verified)"
         % name,
         "scope: %s" % res["latency_us"]["scope"],
         "=" * 74, "",
         "HEADLINE",
         "  attack interception : %d/%d  %s"
         % (res["blocked"], res["n_attack"],
            pct_s(res["blocked"], res["n_attack"])),
         "  false positive (FPR): %d/%d  %s"
         % (len(res["fp"]), res["n_benign"],
            pct_s(len(res["fp"]), res["n_benign"])),
         "  false negative (FNR): %d/%d  %s"
         % (len(res["fn"]), res["n_attack"],
            pct_s(len(res["fn"]), res["n_attack"])),
         "",
         "PER HEADLINE BUCKET",
         "  %-10s %5s %8s %7s %8s %7s" % (
             "bucket", "atk", "block%", "FNR%", "benign", "FPR%")]
    for b, s in res["per_bucket"].items():
        L.append("  %-10s %5d %7.1f%% %6.1f%% %8d %6.1f%%" % (
            b, s["attack"], s["interception"], s["fnr"], s["benign"],
            s["fpr"]))
    L += ["", "PER ESCAPE VARIANT (attack vectors only)",
          "  %-9s %5s %7s %8s" % ("variant", "n", "block", "block%")]
    for k, s in res["per_variant"].items():
        L.append("  %-9s %5d %7d %7.1f%%" % (
            k, s["total"], s["blocked"], s["interception"]))
    la = res["latency_us"]
    L += ["", "LATENCY (in-process routing, us)",
          "  P50=%.1f  P95=%.1f  P99=%.1f  mean=%.1f  max=%.1f" % (
              la["p50"], la["p95"], la["p99"], la["mean"], la["max"]),
          "", "RULE HITS"]
    for r, c in res["rule_hits"].items():
        L.append("  %-28s %d" % (r, c))
    L += ["", "MISS MATRIX (family | variant -> FN / family total)"]
    for k, v in res["miss_matrix"].items():
        L.append("  %-46s %2d / %d" % (k, v["fn"], v["family_total"]))
    if res["schema_mismatch"]:
        L += ["", "SCHEMA LABEL MISMATCH (%d)" % len(res["schema_mismatch"])]
        for f, gg, got in res["schema_mismatch"][:20]:
            L.append("  field=%s intended=%s got=%s" % (f, gg, got))
    L += ["", "FN DETAIL (first 50)"]
    for c in res["fn"][:50]:
        lock = " [LOCKED]" if c["locked"] else ""
        L.append("  %-22s %-8s %-11s %s%s" % (
            c["family"], c["variant"], c["gg_class"],
            c["payload"].replace("\n", "\\n"), lock))
    if res["fp"]:
        L += ["", "FP DETAIL"]
        for c in res["fp"][:50]:
            L.append("  %-11s rule=%-24s %s" % (
                c["gg_class"], c["rule"],
                c["payload"].replace("\n", "\\n")))
    L += ["",
          "Public byte-frozen benchmark (CC-BY-SA-4.0). Reproduced by the open "
          "in-process reference guard; latency is in-process routing scope, "
          "not the proprietary fail-closed engine."]
    return "\n".join(L)


# ---------------------------------------------------------------------------
# holdout gate / ledger
# ---------------------------------------------------------------------------

def gate_holdout(release):
    os.makedirs(RUN_DIR, exist_ok=True)
    ledger = {"official_holdout_runs": []}
    if os.path.exists(LEDGER):
        ledger = json.load(open(LEDGER, encoding="utf-8"))
    if not release:
        print("REFUSED: holdout is sealed before the rule freeze. Iterate on "
              "the dev split only.\n"
              "Official post-freeze run:\n"
              "  python scripts/eval_vector_pool.py holdout --release\n"
              "official runs recorded: %d"
              % len(ledger["official_holdout_runs"]))
        return False
    if ledger["official_holdout_runs"]:
        print("REFUSED: an official holdout run already exists:")
        print(json.dumps(ledger["official_holdout_runs"], indent=2,
                         ensure_ascii=False))
        print("Rotate eval/runs/holdout-ledger.json only by explicit operator "
              "decision.")
        return False
    return True


def record_holdout(res, hashes):
    os.makedirs(RUN_DIR, exist_ok=True)
    ledger = {"official_holdout_runs": []}
    if os.path.exists(LEDGER):
        ledger = json.load(open(LEDGER, encoding="utf-8"))
    ledger["official_holdout_runs"].append({
        "date": time.strftime("%Y-%m-%d"),
        "rule_freeze_tag": "PRE-FREEZE (normalization tier not yet built)",
        "manifest_hashes": hashes,
        "interception": res["interception"], "fpr": res["fpr"],
        "fnr": res["fnr"],
        "note": "Ledger plumbing only; the citable run happens after the "
                "rule freeze, once."})
    json.dump(ledger, open(LEDGER, "w", encoding="utf-8"), indent=2,
              ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["smoke", "dev", "holdout"])
    ap.add_argument("--release", action="store_true")
    args = ap.parse_args()

    if args.split == "holdout":
        print("The holdout split is sealed and is intentionally NOT distributed "
              "with this public repository. It exists for a single post-freeze, "
              "no-tuning confirmation by the authors. Reproduce against the "
              "published 'dev' and 'smoke' splits instead.")
        return 2

    rows, manifest = load_split(args.split)
    res = evaluate(rows)
    text = render_text(args.split, res)
    print(text)
    os.makedirs(RUN_DIR, exist_ok=True)
    tag = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.join(RUN_DIR, "%s-%s" % (args.split, tag))
    open(base + ".txt", "w", encoding="utf-8").write(text)
    json.dump(res, open(base + ".json", "w", encoding="utf-8"), indent=2,
              ensure_ascii=False)
    print("\nwrote %s.{txt,json}" % base)

    if args.split == "smoke":
        return 0 if res["blocked"] == res["n_attack"] and not res["fp"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
