#!/usr/bin/env python3
"""Render benchmark plots and a markdown summary table from CSVs in /results."""

import csv
import os
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = "/results"

def load_summary():
    rows = []
    with open(os.path.join(RESULTS_DIR, "bench_summary.csv")) as f:
        reader = csv.DictReader(f)
        for r in reader:
            for k in ("median_ns", "mean_ns", "stddev_ns", "p95_ns", "p99_ns"):
                r[k] = float(r[k])
            rows.append(r)
    return rows

def load_sizes():
    rows = []
    with open(os.path.join(RESULTS_DIR, "bench_sizes.csv")) as f:
        reader = csv.DictReader(f)
        for r in reader:
            r["bytes"] = int(r["bytes"])
            rows.append(r)
    return rows

def plot_handshake_latency(summary):
    handshake = [r for r in summary if r["operation"] == "handshake_synth"]
    backends = [r["backend"] for r in handshake]
    medians_ms = [r["median_ns"] / 1e6 for r in handshake]
    stds_ms    = [r["stddev_ns"] / 1e6 for r in handshake]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(backends, medians_ms, yerr=stds_ms, capsize=8, color=["#3b82f6", "#f59e0b"])
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Synthetic handshake: median ± stddev")
    for i, v in enumerate(medians_ms):
        ax.text(i, v, f"{v:.2f} ms", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS_DIR, "handshake_latency.png"), dpi=120)
    plt.close(fig)

def plot_per_op(summary):
    ops = ["kem_keygen", "kem_encaps", "kem_decaps",
           "sig_keygen", "sig_sign", "sig_verify",
           "aead_encrypt_1k", "aead_decrypt_1k"]
    by_backend = defaultdict(dict)
    for r in summary:
        by_backend[r["backend"]][r["operation"]] = r["median_ns"]

    backends = sorted(by_backend.keys())
    x = np.arange(len(ops))
    width = 0.35
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, bk in enumerate(backends):
        vals = [by_backend[bk].get(op, 0) for op in ops]
        ax.bar(x + (i - 0.5) * width, vals, width, label=f"Scheme {bk}")
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(ops, rotation=30, ha="right")
    ax.set_ylabel("Median latency (ns, log scale)")
    ax.set_title("Per-operation latency (log-y)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS_DIR, "per_op_latency.png"), dpi=120)
    plt.close(fig)

def plot_sizes(sizes):
    artifacts = ["kem_pk", "kem_sk", "kem_ct", "sig_pk", "sig_max", "handshake_total"]
    by_backend = defaultdict(dict)
    for r in sizes:
        by_backend[r["backend"]][r["artifact"]] = r["bytes"]
    backends = sorted(by_backend.keys())
    x = np.arange(len(artifacts))
    width = 0.35
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, bk in enumerate(backends):
        vals = [by_backend[bk].get(a, 0) for a in artifacts]
        ax.bar(x + (i - 0.5) * width, vals, width, label=f"Scheme {bk}")
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(artifacts, rotation=30, ha="right")
    ax.set_ylabel("Bytes (log scale)")
    ax.set_title("Artifact sizes A vs B")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS_DIR, "artifact_sizes.png"), dpi=120)
    plt.close(fig)

def print_markdown_table(summary, sizes):
    by_op = defaultdict(dict)
    for r in summary:
        by_op[r["operation"]][r["backend"]] = r["median_ns"]
    ops = sorted(by_op.keys())
    print()
    print("| Operation | Scheme A median (us) | Scheme B median (us) |")
    print("|---|---:|---:|")
    for op in ops:
        a = by_op[op].get("A", 0) / 1000
        b = by_op[op].get("B", 0) / 1000
        print(f"| {op} | {a:.2f} | {b:.2f} |")

    by_art = defaultdict(dict)
    for r in sizes:
        by_art[r["artifact"]][r["backend"]] = r["bytes"]
    print()
    print("| Artifact | Scheme A (bytes) | Scheme B (bytes) |")
    print("|---|---:|---:|")
    for a in sorted(by_art.keys()):
        ax = by_art[a].get("A", 0)
        bx = by_art[a].get("B", 0)
        print(f"| {a} | {ax} | {bx} |")

def main():
    summary = load_summary()
    sizes = load_sizes()
    plot_handshake_latency(summary)
    plot_per_op(summary)
    plot_sizes(sizes)
    print_markdown_table(summary, sizes)

if __name__ == "__main__":
    main()
