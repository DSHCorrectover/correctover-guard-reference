#!/usr/bin/env python3
"""Figure W4-1: four-panel publication-style view of the frozen dev split.

Reads a eval/runs/dev-*.json produced by eval_vector_pool.py and renders a
2x2 figure in the host-star scatter + median-trend idiom:

  A  Verdict latency vs payload length        (engine cost stays flat)
  B  Interception vs escape-variant rank      (plain strong, encodings gap)
  C  Payload length vs escape-variant rank    (obfuscation inflation)
  D  Family interception vs rule family       (coverage by attack family)

Honesty: this is the pre-normalization dev baseline; base64/hex/NFKC gaps are
the documented target of the normalization tier, not hidden.
"""

from __future__ import annotations

import glob
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.dirname(os.path.dirname(HERE))
RUNS = os.path.join(SDK, "eval", "runs")
OUT = os.path.join(SDK, "eval", "figures")

# Okabe-Ito-derived muted class colors, echo the reference's blue/orange/red
CLASS_COLOR = {
    "command": "#4C9AC4",      # blue   (Terrestrial-like)
    "url": "#E8A33D",          # amber  (Neptune-like)
    "credential": "#C95E50",   # red    (Gas Giant-like)
}
BENIGN_COLOR = "#8A8F98"
TREND = "#1f1f1f"
VAR_LABELS = ["plain", "base64", "hex", "nfkc", "split", "lexical"]
VAR_RANK = {v: i for i, v in enumerate(VAR_LABELS)}

# families grouped by headline class, in engine rule order
FAMILY_ORDER = [
    "command-expansion", "shell-chaining", "downloader-pipe",
    "sensitive-file-read", "force-delete-root", "reverse-shell",
    "powershell-cradle", "destructive-sql", "chmod-danger",
    "cloud-metadata-url", "cloud-credential-path", "internal-endpoint-url",
    "credential-secret", "credential-exfiltration",
    "money-bound", "ordinary-smuggle",
]

# short axis labels; full names live in the eval report / paper caption
FAMILY_SHORT = {
    "command-expansion": "cmd-exp",
    "shell-chaining": "shell-chain",
    "downloader-pipe": "dl-pipe",
    "sensitive-file-read": "file-read",
    "force-delete-root": "rm-root",
    "reverse-shell": "rev-shell",
    "powershell-cradle": "ps-cradle",
    "destructive-sql": "sql-drop",
    "chmod-danger": "chmod",
    "cloud-metadata-url": "metadata-url",
    "cloud-credential-path": "cred-path",
    "internal-endpoint-url": "intranet-url",
    "credential-secret": "secret",
    "credential-exfiltration": "exfil",
    "money-bound": "money-limit",
    "ordinary-smuggle": "smuggle",
}


def latest_dev():
    files = sorted(glob.glob(os.path.join(RUNS, "dev-*.json")))
    if not files:
        sys.exit("no eval/runs/dev-*.json; run eval_vector_pool.py dev first")
    return files[-1]


def median_trend(xs, ys, bins):
    """Binned median, reported at bin centers; a bin with <3 pts is skipped."""
    cx, cy = [], []
    for lo, hi in zip(bins[:-1], bins[1:]):
        sel = [y for x, y in zip(xs, ys) if lo <= x < hi]
        if len(sel) >= 3:
            cx.append((lo + hi) / 2)
            cy.append(float(np.median(sel)))
    return cx, cy


def main():
    # argv: [run_json] [phase]  phase in {"pre","post"} (default post, since
    # the current engine is the post-normalization build)
    path = sys.argv[1] if len(sys.argv) > 1 else latest_dev()
    phase = sys.argv[2] if len(sys.argv) > 2 else "post"
    if phase == "pre":
        phase_word = "pre-normalization baseline"
        out_tag = "dev-baseline-pre"
        closing = "pre-normalization self-eval, not a public benchmark."
    else:
        phase_word = "post-normalization (evidence-view tier)"
        out_tag = "dev-baseline-post"
        closing = ("post-normalization self-eval; same frozen split as the "
                   "pre figure; not a public benchmark.")
    data = json.load(open(path, encoding="utf-8"))
    pts = data["points"]
    atk = [p for p in pts if p["expected_deny"]]
    ben = [p for p in pts if not p["expected_deny"]]

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.labelsize": 10,
        "axes.titlesize": 10,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 7.5,
        "axes.grid": True,
        "grid.color": "#e8e8ec",
        "grid.linewidth": 0.7,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })

    fig, axes = plt.subplots(2, 2, figsize=(11.2, 9.4))
    fig.suptitle(
        "Figure W4-1 — G-G Parameter-Risk Pool: Engine Behaviour Across the "
        "Escape-Variant Matrix (dev split, n=400, pre-normalization baseline)",
        fontsize=12.5, fontweight="bold", y=0.985)

    rng = np.random.default_rng(20261017)

    def jitter(vals, amount=0.16):
        return np.array(vals) + rng.uniform(-amount, amount, len(vals))

    def panel_letter(ax, ch):
        ax.text(-0.10, 1.06, ch, transform=ax.transAxes,
                fontsize=13, fontweight="bold")

    # ---- A: latency vs payload length ------------------------------------
    ax = axes[0, 0]
    for cls in ("command", "url", "credential"):
        sub = [p for p in atk if p["gg_class"] == cls]
        ax.scatter([p["payload_len"] for p in sub],
                   [p["latency_us"] for p in sub],
                   s=7, alpha=0.55, color=CLASS_COLOR[cls],
                   label={"command": "command-string",
                          "url": "url-endpoint",
                          "credential": "credential-value"}[cls],
                   edgecolors="none", rasterized=True)
    xs = [p["payload_len"] for p in atk]
    ys = [p["latency_us"] for p in atk]
    bins = np.quantile(xs, np.linspace(0, 1, 9))
    bins = np.unique(bins)
    cx, cy = median_trend(xs, ys, bins)
    ax.plot(cx, cy, color=TREND, lw=2.6, label="median trend", zorder=5)
    ax.set_xscale("log")
    ax.set_ylim(0, max(ys) * 1.05)
    ax.set_xlabel("Payload length (bytes, log scale)")
    ax.set_ylabel("Verdict latency [µs]")
    ax.set_title("Routing cost vs input size")
    ax.legend(frameon=False, loc="upper right")

    # ---- B: interception vs variant rank ---------------------------------
    ax = axes[0, 1]
    # benign points along y=0
    bx = jitter([VAR_RANK["plain"] for _ in ben], 0.22)
    ax.scatter(bx, np.zeros(len(ben)), s=6, alpha=0.30,
               color=BENIGN_COLOR, label="benign (0 FPR)",
               marker="^", edgecolors="none", rasterized=True)
    for cls in ("command", "url", "credential"):
        sub = [p for p in atk if p["gg_class"] == cls]
        yv = [1.0 if p["blocked"] else 0.0 for p in sub]
        ax.scatter(jitter([p["variant_rank"] for p in sub]),
                   np.array(yv) + rng.uniform(-0.03, 0.03, len(yv)),
                   s=8, alpha=0.5, color=CLASS_COLOR[cls],
                   label={"command": "command-string",
                          "url": "url-endpoint",
                          "credential": "credential-value"}[cls],
                   edgecolors="none", rasterized=True)
    # per-variant interception median trend (all attacks)
    med_x, med_y = [], []
    for vi, v in enumerate(VAR_LABELS):
        sub = [p for p in atk if p["variant"] == v]
        if sub:
            med_x.append(vi)
            med_y.append(np.mean([1.0 if p["blocked"] else 0.0
                                  for p in sub]))
    ax.plot(med_x, med_y, color=TREND, lw=2.8, marker="o", ms=4,
            label="interception rate", zorder=5)
    for xi, yi in zip(med_x, med_y):
        dy = 8 if yi >= 0.25 else -13
        ax.annotate("%.0f%%" % (yi * 100), (xi, yi),
                    textcoords="offset points", xytext=(0, dy),
                    ha="center", fontsize=7.4, fontweight="bold",
                    color=TREND, zorder=6)
    ax.set_xticks(range(6))
    ax.set_xticklabels(VAR_LABELS, rotation=20, ha="right")
    ax.set_ylim(-0.12, 1.12)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["passed (FN)", "blocked"])
    ax.set_xlabel("Escape variant (increasing obfuscation)")
    ax.set_ylabel("Attack verdict")
    ax.set_title("Interception across the six escape variants")
    ax.legend(frameon=False, loc="upper center", ncol=2, fontsize=7,
              bbox_to_anchor=(0.42, 0.30), columnspacing=1.0,
              handletextpad=0.4, labelspacing=0.35)

    # ---- C: payload length vs variant rank -------------------------------
    ax = axes[1, 0]
    for cls in ("command", "url", "credential"):
        sub = [p for p in atk if p["gg_class"] == cls]
        ax.scatter(jitter([p["variant_rank"] for p in sub]),
                   [p["payload_len"] for p in sub],
                   s=7, alpha=0.55, color=CLASS_COLOR[cls],
                   edgecolors="none", rasterized=True)
    med_x, med_y = [], []
    for vi, v in enumerate(VAR_LABELS):
        sub = [p for p in atk if p["variant"] == v]
        if sub:
            med_x.append(vi)
            med_y.append(np.median([p["payload_len"] for p in sub]))
    ax.plot(med_x, med_y, color=TREND, lw=2.8, marker="o", ms=4, zorder=5)
    ax.set_yscale("log")
    ax.set_xticks(range(6))
    ax.set_xticklabels(VAR_LABELS, rotation=20, ha="right")
    ax.set_xlabel("Escape variant")
    ax.set_ylabel("Payload length [bytes, log]")
    ax.set_title("Encoding inflates payload length")

    # ---- D: family interception ------------------------------------------
    ax = axes[1, 1]
    fams_present = [f for f in FAMILY_ORDER
                    if any(p["family"] == f for p in atk)]
    rate = {}
    for f in fams_present:
        sub = [p for p in atk if p["family"] == f]
        rate[f] = np.mean([1.0 if p["blocked"] else 0.0 for p in sub])
    # color dots by the class of the family's vectors
    cls_of = {}
    for f in fams_present:
        sub = [p for p in atk if p["family"] == f]
        cls_of[f] = sub[0]["gg_class"]
    x = np.arange(len(fams_present))
    for cls in ("command", "url", "credential", "money", "ordinary"):
        fs = [f for f in fams_present if cls_of[f] == cls]
        if not fs:
            continue
        col = CLASS_COLOR.get(cls, "#7A6FA8" if cls == "money" else "#9AA0A6")
        ax.scatter([fams_present.index(f) + rng.uniform(-0.12, 0.12)
                    for f in fs],
                   [rate[f] * 100 for f in fs],
                   s=34, alpha=0.85, color=col,
                   label={"money": "money-amount",
                          "ordinary": "ordinary-field"}.get(cls, cls),
                   edgecolors="white", linewidths=0.6, zorder=4)
    ax.plot(x, [rate[f] * 100 for f in fams_present],
            color=TREND, lw=2.2, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels([FAMILY_SHORT[f] for f in fams_present],
                       fontsize=6.6, rotation=45, ha="right")
    ax.set_ylim(-5, 112)
    ax.set_ylabel("Interception rate [%]")
    ax.set_title("Interception by risk family")
    ax.legend(frameon=False, loc="lower left", fontsize=6.8, ncol=3,
              bbox_to_anchor=(0.0, 0.72), columnspacing=1.0,
              handletextpad=0.4, labelspacing=0.3)

    for ax, ch in zip(axes.ravel(), "ABCD"):
        panel_letter(ax, ch)

    manifest_path = os.path.join(
        SDK, "eval", "vector-pool", "manifest.json")
    dev_hash = ""
    if os.path.exists(manifest_path):
        man = json.load(open(manifest_path, encoding="utf-8"))
        dev_hash = man.get("splits", {}).get("dev", {}).get(
            "sha256_file", "")
    hash_note = ("dev.jsonl SHA-256 %s… · " % dev_hash[:16]) if dev_hash else ""

    fig.text(
        0.5, 0.006,
        "Correctover Guard vW4 · frozen dev split (200 attacks / 200 benign) · "
        "%sbyte-frozen, individually SHA-256 addressed · open in-process reference "
        "(rule surface + evidence views; proprietary signing core excluded) · "
        "trend = binned median / per-group mean · "
        "%s" % (hash_note, closing),
        ha="center", fontsize=7.2, color="#555")

    fig.subplots_adjust(hspace=0.58, wspace=0.22,
                        top=0.90, bottom=0.15, left=0.08, right=0.97)

    os.makedirs(OUT, exist_ok=True)
    for ext in ("png", "pdf"):
        fp = os.path.join(OUT, "figure-w4-1-%s.%s" % (out_tag, ext))
        fig.savefig(fp, dpi=300 if ext == "png" else None,
                    bbox_inches="tight")
        print("wrote", fp)


if __name__ == "__main__":
    main()
